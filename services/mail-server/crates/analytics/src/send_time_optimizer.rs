//! Send-time optimizer – Bayesian smoothing, hour/day distributions, optimal windows.
//!
//! # Security (O-11.5)
//! Email hashing uses HMAC-SHA256 with a configurable salt key to prevent
//! rainbow-table attacks on cache keys.

use chrono::{Offset as _, Utc};

use crate::types::*;

pub use crate::email_hash::hash_email;

/// Global prior probabilities for hours (24) – peak at 10 AM.
const HOUR_PRIORS: [f64; 24] = [
    0.011, 0.0055, 0.0033, 0.0033, 0.0055, 0.011, 0.022, 0.0439, 0.0768, 0.0988, 0.1207, 0.1098,
    0.0878, 0.0768, 0.0659, 0.0549, 0.0439, 0.0384, 0.0329, 0.0274, 0.022, 0.0165, 0.0132, 0.0088,
];

/// Global prior probabilities for days (Mon=0..Sun=6) – peak on Tuesday.
const DAY_PRIORS: [f64; 7] = [0.16, 0.18, 0.17, 0.16, 0.14, 0.10, 0.09];

/// Cold-start default:Tuesday 10:00 AM UTC. Rendered in the tenant's LOCAL
/// time via [`local_cold_start_hour`] (F5).
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
    ///
    /// UTC-only (offset 0) — see [`get_optimal_window_for_tenant`] for the
    /// tenant-timezone-aware variant.
    pub async fn get_optimal_window(&self, email: &str) -> anyhow::Result<BulkOptimizationResult> {
        let email_hash = hash_email(email, &self.hmac_key);
        let cache_key = format!("sto:{email_hash}");

        if let Ok(cached) = self.get_cached(&cache_key).await {
            return Ok(cached);
        }

        let profile = self.build_recipient_profile(email, 0).await?;
        let windows = compute_optimal_windows_at_offset(&profile, 0);

        let result = BulkOptimizationResult {
            email_hash: email_hash.clone(),
            windows: windows.clone(),
            confidence: profile.total_events as f64 / (profile.total_events as f64 + 100.0),
            profile_age_days: profile.profile_age_days,
            utc_offset_minutes: 0,
        };

        self.set_cached(&cache_key, &result, 86400).await.ok();
        Ok(result)
    }

    /// Get optimal send window for a recipient in the TENANT'S timezone (F5).
    ///
    /// The hour buckets are meaningless in UTC for non-UTC recipients, so the
    /// tenant's offset (from `tenants.settings` — see
    /// [`utc_offset_minutes_from_settings`]) shifts both the hour extraction
    /// and the cold-start hour; the result labels the applied offset.
    pub async fn get_optimal_window_for_tenant(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> anyhow::Result<BulkOptimizationResult> {
        let email_hash = hash_email(email, &self.hmac_key);
        // Tenant-scoped key: the same recipient under a different tenant can
        // resolve a different offset (and must not poison the other's cache).
        let cache_key = format!("sto:{tenant_id}:{email_hash}");

        if let Ok(cached) = self.get_cached(&cache_key).await {
            return Ok(cached);
        }

        let offset = self.tenant_utc_offset_minutes(tenant_id).await?;
        let profile = self.build_recipient_profile(email, offset).await?;
        let windows = compute_optimal_windows_at_offset(&profile, offset);

        let result = BulkOptimizationResult {
            email_hash: email_hash.clone(),
            windows: windows.clone(),
            confidence: profile.total_events as f64 / (profile.total_events as f64 + 100.0),
            profile_age_days: profile.profile_age_days,
            utc_offset_minutes: offset,
        };

        self.set_cached(&cache_key, &result, 86400).await.ok();
        Ok(result)
    }

    /// Read the tenant's UTC offset from `tenants.settings` (F5).
    ///
    /// No existing key convention was found in the settings readers
    /// (`billingCurrency` camelCase is the closest precedent), so BOTH a
    /// `timezone` IANA name and an explicit `utc_offset_minutes` number are
    /// supported — see [`utc_offset_minutes_from_settings`]. Unknown tenants
    /// or absent keys default to 0 (UTC), never an error:the optimizer must
    /// still produce a window.
    async fn tenant_utc_offset_minutes(&self, tenant_id: &str) -> anyhow::Result<i32> {
        let settings: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT settings FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(settings
            .map(|(s,)| utc_offset_minutes_from_settings(&s))
            .unwrap_or(0))
    }

    /// Build recipient profile from engagement data.
    ///
    /// `utc_offset_minutes` shifts the hour/day-of-week extraction into the
    /// tenant's local time (F5):`timestamp AT TIME ZONE 'UTC'` pins the
    /// wall-clock reading to UTC regardless of the session timezone, then the
    /// interval (parameterised, not string-interpolated) moves it local.
    async fn build_recipient_profile(
        &self,
        email: &str,
        utc_offset_minutes: i32,
    ) -> anyhow::Result<RecipientProfile> {
        let rows = sqlx::query_as::<_, (i32, i32, i64)>(
            "SELECT EXTRACT(HOUR FROM (timestamp AT TIME ZONE 'UTC') \
                 + make_interval(mins => $2))::int as hour, \
             EXTRACT(DOW FROM (timestamp AT TIME ZONE 'UTC') \
                 + make_interval(mins => $2))::int as dow, \
             COUNT(*) as cnt \
             FROM events \
             WHERE recipient = $1 AND event_type IN ('opened', 'clicked') \
             GROUP BY hour, dow",
        )
        .bind(email)
        .bind(utc_offset_minutes)
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

/// Compute top-3 optimal send windows from a recipient profile (UTC).
///
/// Kept as the offset-0 entry point for existing callers; see
/// [`compute_optimal_windows_at_offset`] for tenant-timezone-aware use.
pub fn compute_optimal_windows(profile: &RecipientProfile) -> Vec<OptimalSendWindow> {
    compute_optimal_windows_at_offset(profile, 0)
}

/// [`compute_optimal_windows`] with the tenant's UTC offset applied (F5).
///
/// The profile's hour distribution must already be LOCAL (built with the
/// same offset — see `build_recipient_profile`); the offset here shifts the
/// cold-start hour, whose constant is defined in UTC, into local time.
/// `HOUR_PRIORS`/`DAY_PRIORS` model human behaviour in LOCAL time and need
/// no shift.
pub fn compute_optimal_windows_at_offset(
    profile: &RecipientProfile,
    utc_offset_minutes: i32,
) -> Vec<OptimalSendWindow> {
    let alpha = dynamic_alpha(profile.total_events as f64);
    let cold_start_hour = local_cold_start_hour(utc_offset_minutes);

    // Cold start:return the default Tuesday 10 AM in LOCAL time
    if profile.total_events < 5 {
        return vec![OptimalSendWindow {
            hour: cold_start_hour,
            day: COLD_START_DAY,
            score: HOUR_PRIORS[cold_start_hour as usize] * DAY_PRIORS[COLD_START_DAY as usize],
            confidence: 0.0,
        }];
    }

    // Compute smoothed scores for each (hour, day) pair
    let mut windows: Vec<OptimalSendWindow> = Vec::with_capacity(24 * 7);

    for (hour, hour_prior) in HOUR_PRIORS.iter().enumerate() {
        let hour_posterior = bayesian_smooth(
            profile.hour_distribution.hours[hour],
            profile.total_events as f64,
            *hour_prior,
            alpha,
        );

        for (day, day_prior) in DAY_PRIORS.iter().enumerate() {
            let day_posterior = bayesian_smooth(
                profile.day_distribution.days[day],
                profile.total_events as f64,
                *day_prior,
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

/// The UTC cold-start hour (10:00) expressed in local time under the given
/// offset, wrapped into 0..=24 hours. The day bucket stays put — a cold
/// start has no data to justify a weekday shift.
fn local_cold_start_hour(utc_offset_minutes: i32) -> u32 {
    let minutes = COLD_START_HOUR as i64 * 60 + utc_offset_minutes as i64;
    (minutes.div_euclid(60).rem_euclid(24)) as u32
}

/// Resolve a tenant's UTC offset (minutes) from its `settings` JSONB (F5).
///
/// No key convention existed among the settings readers, so both spellings
/// are supported (in this precedence):
/// 1. `timezone` — IANA name (`"Europe/Tallinn"`), resolved via chrono-tz
///    to the offset in effect NOW (per-event DST history is out of scope for
///    hour-bucket histograms; the label on the result makes the applied
///    offset visible). An unresolvable name falls through to (2).
/// 2. `utc_offset_minutes` — explicit number (e.g. `120`), rounded.
/// 3. Default `0` (UTC).
///
/// Out-of-range values (|offset| > 24 h) are treated as unset.
pub fn utc_offset_minutes_from_settings(settings: &serde_json::Value) -> i32 {
    if let Some(name) = settings.get("timezone").and_then(|v| v.as_str()) {
        if let Ok(tz) = name.parse::<chrono_tz::Tz>() {
            // `local_minus_utc` is in SECONDS — convert to the minutes unit
            // this module (and `utc_offset_minutes`) standardises on.
            return Utc::now()
                .with_timezone(&tz)
                .offset()
                .fix()
                .local_minus_utc()
                / 60;
        }
    }
    if let Some(raw) = settings
        .get("utc_offset_minutes")
        .and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|i| i as f64)))
    {
        let minutes = raw.round() as i32;
        if (-1440..=1440).contains(&minutes) {
            return minutes;
        }
    }
    0
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

    // ── F5:tenant-timezone offset handling ─────────────────────────────

    fn cold_profile() -> RecipientProfile {
        RecipientProfile {
            hour_distribution: HourDistribution {
                hours: vec![0.0; 24],
            },
            day_distribution: DayDistribution { days: vec![0.0; 7] },
            total_events: 0,
            profile_age_days: 0,
        }
    }

    #[test]
    fn test_local_cold_start_hour_shifts_and_wraps() {
        // UTC 10:00 unchanged.
        assert_eq!(local_cold_start_hour(0), 10);
        // UTC+3 (Tallinn summer) → 13:00 local.
        assert_eq!(local_cold_start_hour(180), 13);
        // UTC-5 (New York winter) → 05:00 local.
        assert_eq!(local_cold_start_hour(-300), 5);
        // +14 h (Kiritimati) wraps past midnight.
        assert_eq!(local_cold_start_hour(14 * 60), 0);
        // -12 h wraps backwards.
        assert_eq!(local_cold_start_hour(-12 * 60), 22);
    }

    #[test]
    fn test_cold_start_uses_local_hour() {
        let windows = compute_optimal_windows_at_offset(&cold_profile(), 180);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].hour, 13, "UTC+3 cold start must be 10:00 local");
        assert_eq!(windows[0].day, COLD_START_DAY);
    }

    #[test]
    fn test_utc_entry_point_unchanged() {
        let windows = compute_optimal_windows(&cold_profile());
        assert_eq!(windows[0].hour, COLD_START_HOUR);
    }

    #[test]
    fn test_offset_respects_local_peak() {
        // Engagement peaked at local 08:00 for a UTC+2 tenant.
        let mut hours = vec![0.0; 24];
        hours[8] = 1.0;
        let profile = RecipientProfile {
            hour_distribution: HourDistribution { hours },
            day_distribution: DayDistribution {
                days: vec![1.0 / 7.0; 7],
            },
            total_events: 100,
            profile_age_days: 30,
        };
        let windows = compute_optimal_windows_at_offset(&profile, 120);
        assert!(!windows.is_empty());
        assert_eq!(windows[0].hour, 8, "top window must stay in local hours");
    }

    #[test]
    fn test_settings_offset_iana_name_resolves() {
        // Europe/Tallinn is UTC+2 in winter / UTC+3 in summer — either is a
        // valid DST offset; assert it round-trips to one of those.
        let settings = serde_json::json!({ "timezone": "Europe/Tallinn" });
        let offset = utc_offset_minutes_from_settings(&settings);
        assert!(offset == 120 || offset == 180, "got {offset}");
    }

    #[test]
    fn test_settings_offset_explicit_minutes() {
        assert_eq!(
            utc_offset_minutes_from_settings(&serde_json::json!({ "utc_offset_minutes": 330 })),
            330
        );
        assert_eq!(
            utc_offset_minutes_from_settings(&serde_json::json!({ "utc_offset_minutes": -300 })),
            -300
        );
        // Fractional minutes round.
        assert_eq!(
            utc_offset_minutes_from_settings(&serde_json::json!({ "utc_offset_minutes": 90.4 })),
            90
        );
    }

    #[test]
    fn test_settings_offset_defaults_and_rejects_garbage() {
        // Absent keys → UTC.
        assert_eq!(utc_offset_minutes_from_settings(&serde_json::json!({})), 0);
        assert_eq!(
            utc_offset_minutes_from_settings(&serde_json::json!({ "unrelated": true })),
            0
        );
        // Unresolvable IANA name falls through to utc_offset_minutes.
        assert_eq!(
            utc_offset_minutes_from_settings(&serde_json::json!({
                "timezone": "Mars/Olympus_Mons", "utc_offset_minutes": 60
            })),
            60
        );
        // Out-of-range explicit offset is ignored.
        assert_eq!(
            utc_offset_minutes_from_settings(&serde_json::json!({ "utc_offset_minutes": 9999 })),
            0
        );
        // Wrong types ignored.
        assert_eq!(
            utc_offset_minutes_from_settings(&serde_json::json!({ "utc_offset_minutes": "2h" })),
            0
        );
    }

    #[test]
    fn test_settings_offset_iana_takes_precedence() {
        let settings = serde_json::json!({ "timezone": "UTC", "utc_offset_minutes": 480 });
        assert_eq!(utc_offset_minutes_from_settings(&settings), 0);
    }
}
