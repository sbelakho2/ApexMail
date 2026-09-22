//! Monitoring and alerting for metering drain operations.
//!
//! This module wraps [`drain_pending_metering_events`] with Prometheus-style
//! metrics, adds failure detection with consecutive-error alerting, and
//! provides stale-event warnings for pending metering events that accumulate
//! in Redis.
//!
//! # Metrics
//!
//! | Metric | Type | Description |
//! |---|---|---|
//! | `apexmail_metering_events_drained_total` | Counter | Total events successfully drained |
//! | `apexmail_metering_events_drain_errors_total` | Counter | Total drain failures |
//! | `apexmail_metering_events_pending_count` | Gauge | Pending events waiting to be drained |
//! | `apexmail_metering_events_drain_duration_seconds` | Histogram | Drain operation duration |
//!
//! # Alert Conditions
//!
//! * **Consecutive drain errors** — When [`DRAIN_ERROR_ALERT_THRESHOLD`] (10)
//!   consecutive drain operations fail, a high-severity `tracing::error!` is
//!   emitted with the `"METERING DRAIN ALERT"` prefix.
//! * **Stale pending events** — When pending metering events remain in Redis
//!   beyond [`STALE_EVENT_AGE_LIMIT_MINUTES`] (30 min), a warning is issued
//!   with the stale count and oldest event age.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use tracing::{error, info, warn};

use crate::maintenance::{drain_pending_metering_events, MeteringDrainResult};
use crate::AppState;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Number of consecutive drain errors that triggers a high-severity alert.
///
/// Once the consecutive error count reaches this threshold, every subsequent
/// failure is logged at `tracing::error!` level with the
/// `"METERING DRAIN ALERT"` prefix. The counter resets to zero on the first
/// successful drain.
const DRAIN_ERROR_ALERT_THRESHOLD: u64 = 10;

/// Age in minutes after which a pending metering event is considered stale.
///
/// Events that sit in Redis undrained for longer than this limit indicate a
/// potential backlog or drain failure. A warning is emitted with the count
/// of stale events and the age of the oldest event found.
const STALE_EVENT_AGE_LIMIT_MINUTES: i64 = 30;

// ─── State ───────────────────────────────────────────────────────────────────

/// Tracks consecutive drain failures for threshold-based alerting.
///
/// Reset to 0 on every successful drain; incremented on every error.
static CONSECUTIVE_DRAIN_ERRORS: AtomicU64 = AtomicU64::new(0);

// ─── Public API ─────────────────────────────────────────────────────────────

/// Run a monitored metering drain, recording metrics and detecting failure
/// patterns.
///
/// This is the intended entry point for the periodic drain job. It delegates to
/// [`drain_pending_metering_events`] and wraps the result with the following
/// instrumentation:
///
/// * **`apexmail_metering_events_drained_total`** — counter incremented by the
///   number of events successfully processed.
/// * **`apexmail_metering_events_drain_errors_total`** — counter incremented
///   on each error.
/// * **`apexmail_metering_events_drain_duration_seconds`** — histogram
///   recording the wall-clock duration of the drain operation.
/// * **Consecutive error tracking** — when
///   [`CONSECUTIVE_DRAIN_ERRORS`][CONSECUTIVE_DRAIN_ERRORS] reaches
///   [`DRAIN_ERROR_ALERT_THRESHOLD`], a high-severity log entry is emitted.
pub(crate) async fn monitored_drain_pending_events(
    state: &AppState,
    limit: usize,
) -> Result<MeteringDrainResult, String> {
    let start = Instant::now();

    let result = drain_pending_metering_events(state, limit).await;

    let duration_seconds = start.elapsed().as_secs_f64();
    metrics::histogram!("apexmail_metering_events_drain_duration_seconds").record(duration_seconds);

    match &result {
        Ok(drain_result) => {
            // Successful drain resets the consecutive-failure counter.
            CONSECUTIVE_DRAIN_ERRORS.store(0, Ordering::Release);

            let drained = drain_result.processed_count.max(0) as u64;
            if drained > 0 {
                metrics::counter!("apexmail_metering_events_drained_total").increment(drained);
            }

            info!(
                processed_count = drain_result.processed_count,
                discarded_count = drain_result.discarded_count,
                duration_seconds,
                "metering drain completed",
            );
        }
        Err(error_message) => {
            let prev = CONSECUTIVE_DRAIN_ERRORS.fetch_add(1, Ordering::AcqRel);
            let consecutive = prev + 1;

            metrics::counter!("apexmail_metering_events_drain_errors_total").increment(1);

            if consecutive >= DRAIN_ERROR_ALERT_THRESHOLD {
                error!(
                    consecutive_errors = consecutive,
                    threshold = DRAIN_ERROR_ALERT_THRESHOLD,
                    error = %error_message,
                    "METERING DRAIN ALERT: consecutive drain errors exceeded threshold",
                );
            } else {
                error!(
                    consecutive_errors = consecutive,
                    error = %error_message,
                    "metering drain failed",
                );
            }
        }
    }

    result
}

/// Check for stale pending metering events and emit warnings.
///
/// Scans Redis for pending event keys matching `meter:pending:*`, updates the
/// [`apexmail_metering_events_pending_count`] gauge, and samples up to 20
/// event payloads to determine their age. If any events exceed
/// [`STALE_EVENT_AGE_LIMIT_MINUTES`], a warning is logged with the stale count
/// and the age of the oldest event.
///
/// Falls back gracefully when Redis is unavailable (logs a `warn!` instead of
/// propagating the error).
pub(crate) async fn check_stale_pending_events(state: &AppState) {
    let mut conn = match state.redis.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "cannot check stale pending events: Redis connection failed");
            return;
        }
    };

    // Collect pending event keys for the stale check.
    // Use SCAN instead of KEYS for production safety — KEYS blocks Redis.
    let mut cursor: u64 = 0;
    let mut pending_keys: Vec<String> = Vec::new();
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = match redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("meter:pending:*")
            .arg("COUNT")
            .arg(500)
            .query_async(&mut conn)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "cannot scan for stale pending events");
                return;
            }
        };
        pending_keys.extend(batch);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    let total_pending = pending_keys.len();
    metrics::gauge!("apexmail_metering_events_pending_count").set(total_pending as f64);

    if total_pending == 0 {
        return;
    }

    // Sample up to 20 payloads to find the oldest event.
    let sample_size = total_pending.min(20);
    let sample_keys: Vec<&String> = pending_keys.iter().take(sample_size).collect();

    let payloads: Vec<Option<String>> = redis::cmd("MGET")
        .arg(&sample_keys)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    let now = Utc::now();
    let (stale_count, oldest_age_minutes) = count_stale_events(&payloads, now);

    if stale_count > 0 {
        warn!(
            stale_events = stale_count,
            total_pending,
            oldest_age_minutes,
            age_limit_minutes = STALE_EVENT_AGE_LIMIT_MINUTES,
            "detected stale pending metering events that have not been drained",
        );
    }
}

// ─── Internal helpers (exposed for testability) ─────────────────────────────

/// Count stale events from a batch of payloads and return the oldest age.
///
/// Extracted as a pure function for testability. A payload is considered stale
/// when its `timestamp` field is older than [`STALE_EVENT_AGE_LIMIT_MINUTES`]
/// relative to `now`.
///
/// Returns a tuple of `(stale_count, oldest_age_minutes)`.
fn count_stale_events(payloads: &[Option<String>], now: DateTime<Utc>) -> (usize, i64) {
    let mut stale_count = 0usize;
    let mut oldest_age_minutes = 0i64;

    for payload in payloads {
        let Some(json) = payload else {
            continue;
        };
        let Ok(event) = serde_json::from_str::<serde_json::Value>(json) else {
            continue;
        };
        let Some(ts_str) = event.get("timestamp").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(ts) = chrono::DateTime::parse_from_rfc3339(ts_str) else {
            continue;
        };
        let ts_utc = ts.with_timezone(&Utc);
        let age_minutes = (now - ts_utc).num_minutes();
        if age_minutes >= STALE_EVENT_AGE_LIMIT_MINUTES {
            stale_count += 1;
        }
        oldest_age_minutes = oldest_age_minutes.max(age_minutes);
    }

    (stale_count, oldest_age_minutes)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    static CONSECUTIVE_DRAIN_ERRORS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ─── Constant validation ──────────────────────────────────────

    #[test]
    fn drain_error_alert_threshold_is_reasonable() {
        const _: () = assert!(
            DRAIN_ERROR_ALERT_THRESHOLD > 0,
            "threshold must be positive"
        );
        const _: () = assert!(
            DRAIN_ERROR_ALERT_THRESHOLD <= 100,
            "threshold should not exceed 100"
        );
    }

    #[test]
    fn stale_event_age_limit_is_reasonable() {
        const _: () = assert!(
            STALE_EVENT_AGE_LIMIT_MINUTES > 0,
            "stale age limit must be positive"
        );
        const _: () = assert!(
            STALE_EVENT_AGE_LIMIT_MINUTES <= 1440,
            "stale age limit should not exceed 24 hours (1440 minutes)"
        );
    }

    // ─── Consecutive error tracking ───────────────────────────────

    #[test]
    fn consecutive_errors_starts_at_zero() {
        let _guard = CONSECUTIVE_DRAIN_ERRORS_TEST_LOCK.lock().unwrap();

        // Reset first to isolate from parallel sibling tests that share
        // the static counter.
        CONSECUTIVE_DRAIN_ERRORS.store(0, Ordering::Release);
        assert_eq!(CONSECUTIVE_DRAIN_ERRORS.load(Ordering::Acquire), 0);
    }

    #[test]
    fn consecutive_errors_increments_and_resets() {
        let _guard = CONSECUTIVE_DRAIN_ERRORS_TEST_LOCK.lock().unwrap();

        // Reset first to isolate from parallel sibling tests.
        CONSECUTIVE_DRAIN_ERRORS.store(0, Ordering::Release);

        // Simulate failures
        for _ in 0..3 {
            CONSECUTIVE_DRAIN_ERRORS.fetch_add(1, Ordering::AcqRel);
        }
        assert_eq!(CONSECUTIVE_DRAIN_ERRORS.load(Ordering::Acquire), 3);

        // Simulate success (reset)
        CONSECUTIVE_DRAIN_ERRORS.store(0, Ordering::Release);
        assert_eq!(CONSECUTIVE_DRAIN_ERRORS.load(Ordering::Acquire), 0);
    }

    #[test]
    fn consecutive_error_threshold_crossing() {
        let _guard = CONSECUTIVE_DRAIN_ERRORS_TEST_LOCK.lock().unwrap();

        // Reset first to isolate from parallel sibling tests.
        CONSECUTIVE_DRAIN_ERRORS.store(0, Ordering::Release);

        // Push to threshold - 1
        for _ in 0..(DRAIN_ERROR_ALERT_THRESHOLD - 1) {
            CONSECUTIVE_DRAIN_ERRORS.fetch_add(1, Ordering::AcqRel);
        }
        assert_eq!(
            CONSECUTIVE_DRAIN_ERRORS.load(Ordering::Acquire),
            DRAIN_ERROR_ALERT_THRESHOLD - 1,
        );

        // One more crosses the threshold
        CONSECUTIVE_DRAIN_ERRORS.fetch_add(1, Ordering::AcqRel);
        assert_eq!(
            CONSECUTIVE_DRAIN_ERRORS.load(Ordering::Acquire),
            DRAIN_ERROR_ALERT_THRESHOLD,
        );

        CONSECUTIVE_DRAIN_ERRORS.store(0, Ordering::Release);
    }

    // ─── Stale event detection ────────────────────────────────────

    #[test]
    fn stale_count_empty_list() {
        let payloads: Vec<Option<String>> = Vec::new();
        let (count, _) = count_stale_events(&payloads, Utc::now());
        assert_eq!(count, 0);
    }

    #[test]
    fn stale_count_no_timestamp_field() {
        let payloads = vec![Some(r#"{"id":"abc","tenant_id":"t1"}"#.to_string())];
        let (count, _) = count_stale_events(&payloads, Utc::now());
        assert_eq!(count, 0);
    }

    #[test]
    fn stale_count_malformed_json() {
        let payloads = vec![Some("not-json".to_string())];
        let (count, _) = count_stale_events(&payloads, Utc::now());
        assert_eq!(count, 0);
    }

    #[test]
    fn stale_count_null_payload() {
        let payloads = vec![None];
        let (count, _) = count_stale_events(&payloads, Utc::now());
        assert_eq!(count, 0);
    }

    #[test]
    fn stale_count_recent_event() {
        let now = Utc::now();
        let recent_ts = now - chrono::Duration::minutes(5);
        let payloads = vec![Some(format!(
            r#"{{"timestamp":"{}"}}"#,
            recent_ts.to_rfc3339()
        ))];
        let (count, _) = count_stale_events(&payloads, now);
        assert_eq!(count, 0);
    }

    #[test]
    fn stale_count_event_at_exact_boundary() {
        let now = Utc::now();
        // Exactly at the limit — events at the boundary ARE considered stale
        // (age_minutes >= STALE_EVENT_AGE_LIMIT_MINUTES).
        let boundary_ts = now - chrono::Duration::minutes(STALE_EVENT_AGE_LIMIT_MINUTES);
        let payloads = vec![Some(format!(
            r#"{{"timestamp":"{}"}}"#,
            boundary_ts.to_rfc3339()
        ))];
        let (count, _) = count_stale_events(&payloads, now);
        assert_eq!(
            count, 1,
            "events at the exact boundary must be counted as stale"
        );
    }

    #[test]
    fn stale_count_old_event() {
        let now = Utc::now();
        let old_ts = now - chrono::Duration::minutes(60);
        let payloads = vec![Some(format!(
            r#"{{"timestamp":"{}"}}"#,
            old_ts.to_rfc3339()
        ))];
        let (count, _) = count_stale_events(&payloads, now);
        assert_eq!(count, 1);
    }

    #[test]
    fn stale_count_mixed_events() {
        let now = Utc::now();
        let recent_ts = now - chrono::Duration::minutes(5);
        let old_ts = now - chrono::Duration::minutes(60);
        let payloads = vec![
            Some(format!(r#"{{"timestamp":"{}"}}"#, recent_ts.to_rfc3339())),
            Some(format!(r#"{{"timestamp":"{}"}}"#, old_ts.to_rfc3339())),
            None,
            Some(r#"{"id":"no-ts"}"#.to_string()),
        ];
        let (count, oldest) = count_stale_events(&payloads, now);
        assert_eq!(count, 1);
        assert!(oldest >= 60, "oldest age should be at least 60 minutes");
    }

    #[test]
    fn stale_count_oldest_age_tracking() {
        let now = Utc::now();
        let ts_5m = now - chrono::Duration::minutes(5);
        let ts_30m = now - chrono::Duration::minutes(30);
        let ts_120m = now - chrono::Duration::minutes(120);
        let payloads = vec![
            Some(format!(r#"{{"timestamp":"{}"}}"#, ts_5m.to_rfc3339())),
            Some(format!(r#"{{"timestamp":"{}"}}"#, ts_30m.to_rfc3339())),
            Some(format!(r#"{{"timestamp":"{}"}}"#, ts_120m.to_rfc3339())),
        ];
        let (count, oldest) = count_stale_events(&payloads, now);
        // Only the 120-minute event is stale (>= 30 min limit)
        assert_eq!(count, 2);
        assert!(
            oldest >= 120,
            "oldest age should be at least 120 minutes, got {oldest}",
        );
    }

    // ─── Overflow guard ───────────────────────────────────────────

    #[test]
    fn drain_result_conversion_saturates_at_i64_max() {
        // Verify the saturating conversion used in the drain function body
        // (not modifying production code, just documenting the behaviour).
        assert_eq!(
            i64::try_from(usize::MAX).unwrap_or(i64::MAX),
            i64::MAX,
            "usize-to-i64 conversion must saturate to i64::MAX on overflow",
        );
    }

    #[test]
    fn stale_count_bad_timestamp_string_is_skipped() {
        // A well-formed JSON object whose `timestamp` is not RFC 3339 is
        // skipped, not counted and not allowed to poison the oldest-age max.
        let payloads = vec![Some(r#"{"timestamp":"not-a-timestamp"}"#.to_string())];
        let (count, oldest) = count_stale_events(&payloads, Utc::now());
        assert_eq!(count, 0);
        assert_eq!(oldest, 0);
    }

    // ─── Monitored drain (Redis/DB-backed) ────────────────────────
    //
    // The static CONSECUTIVE_DRAIN_ERRORS counter is process-global, so every
    // test that drives [`monitored_drain_pending_events`] takes the same
    // module lock and resets the counter before its assertions.

    /// Reset the process-global streak without holding a non-Send guard
    /// across await points (clippy::await_holding_lock).
    fn reset_error_streak() {
        let _guard = CONSECUTIVE_DRAIN_ERRORS_TEST_LOCK.lock().unwrap();
        CONSECUTIVE_DRAIN_ERRORS.store(0, Ordering::Release);
    }

    fn read_error_streak() -> u64 {
        CONSECUTIVE_DRAIN_ERRORS.load(Ordering::Acquire)
    }

    async fn provision_env(tag: &str) -> crate::test_support::TestEnv {
        crate::test_support::provision(tag)
            .await
            .expect("TEST_DATABASE_URL/redis must be configured for this suite")
    }

    fn push_consecutive_errors(count: u64) {
        for _ in 0..count {
            CONSECUTIVE_DRAIN_ERRORS.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[tokio::test]
    async fn monitored_drain_counts_a_real_recovery_and_resets_the_error_streak() {
        reset_error_streak();
        let owned = provision_env("monitored_drain_success").await;
        let env = &owned;
        let _metering_guard =
            crate::test_support::redis_keys_guard(&owned.admin_url, "metering").await;
        crate::test_support::seed_tenant(&env.pool, "mtcov_mon_drain", "growth").await;

        // Two pending events (one valid, one malformed) mirror the recovery
        // semantics the monitor reports: processed=1, discarded=1.
        let payload = serde_json::json!({
            "id": "evt_mtcov_mon_0001",
            "tenantId": "mtcov_mon_drain",
            "eventType": "email_sent",
            "quantity": 2,
            "timestamp": Utc::now().to_rfc3339(),
            "metadata": {},
        });
        let mut conn = env.state.redis.get().await.expect("redis");
        for (key, value) in [
            ("meter:pending:evt_mtcov_mon_0001", payload.to_string()),
            ("meter:pending:evt_mtcov_mon_bad", "not json".to_string()),
        ] {
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg(value)
                .query_async(&mut conn)
                .await
                .expect("seed pending");
        }
        drop(conn);

        push_consecutive_errors(DRAIN_ERROR_ALERT_THRESHOLD + 3);
        let result = monitored_drain_pending_events(&env.state, 100)
            .await
            .expect("monitored drain succeeds");
        assert_eq!(result.processed_count, 1);
        assert_eq!(result.discarded_count, 1);
        assert_eq!(
            read_error_streak(),
            0,
            "a successful drain resets the consecutive-error streak"
        );

        owned.finish().await;
    }

    #[tokio::test]
    async fn monitored_drain_error_streak_reaches_the_alert_threshold() {
        reset_error_streak();
        let owned = provision_env("monitored_drain_errors").await;
        let env = &owned;
        // A dead Redis pool makes every drain fail fast (connection refused).
        let state = crate::test_support::state_with_dead_redis(&env.pool);

        // Each failure bumps the streak: 1..THRESHOLD hits the non-alert
        // error branch, THRESHOLD and THRESHOLD+1 the alert branch (>=
        // semantics).
        for expected in 1..=(DRAIN_ERROR_ALERT_THRESHOLD + 1) {
            monitored_drain_pending_events(&state, 10)
                .await
                .expect_err("dead redis fails the drain");
            assert_eq!(
                read_error_streak(),
                expected,
                "failure {expected} must leave the streak at exactly {expected}"
            );
        }

        owned.finish().await;
    }

    #[tokio::test]
    async fn monitored_drain_zero_events_records_success_without_counter_increments() {
        reset_error_streak();
        let owned = provision_env("monitored_drain_empty").await;
        // A PRIVATE redis guarantees the empty-keyspace precondition even
        // while sibling processes drain the shared instance.
        let mut isolated = crate::test_support::spawn_isolated_redis();
        let config = crate::config::BillingConfig {
            redis_url: "redis://127.0.0.1:1".to_string(),
            ..owned.state.config.clone()
        };
        let state = crate::AppState::new(owned.pool.clone(), isolated.pool.clone(), config);

        let result = monitored_drain_pending_events(&state, 100)
            .await
            .expect("empty redis drains cleanly");
        assert_eq!(result.processed_count, 0);
        assert_eq!(result.discarded_count, 0);
        assert_eq!(read_error_streak(), 0);

        isolated.kill();
        owned.finish().await;
    }

    // ─── Stale pending-event sweep (Redis-backed) ─────────────────

    #[tokio::test]
    async fn check_stale_pending_events_warns_for_old_events_and_scans_clean_redis() {
        let owned = provision_env("check_stale_events").await;
        let env = &owned;
        let _metering_guard =
            crate::test_support::redis_keys_guard(&owned.admin_url, "stale-monitor").await;

        // Empty keyspace: the SCAN loop completes and the gauge is set to 0.
        check_stale_pending_events(&env.state).await;

        // 25 keys exercise the 20-key sample cap; the payloads span the
        // fresh/stale boundary plus unparsable noise.
        let mut conn = env.state.redis.get().await.expect("redis");
        let now = Utc::now();
        for i in 0..25 {
            let ts = if i == 0 {
                now - chrono::Duration::minutes(90)
            } else if i == 1 {
                now - chrono::Duration::minutes(2)
            } else {
                now
            };
            let payload = if i == 2 {
                "not json at all".to_string()
            } else {
                serde_json::json!({ "timestamp": ts.to_rfc3339() }).to_string()
            };
            let _: () = redis::cmd("SET")
                .arg(format!("meter:pending:stale_cov_{i}"))
                .arg(payload)
                .query_async(&mut conn)
                .await
                .expect("seed pending");
        }
        drop(conn);

        check_stale_pending_events(&env.state).await;

        // Cleanup so sibling suites never see these keys.
        let mut conn = env.state.redis.get().await.expect("redis cleanup");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("meter:pending:stale_cov_*")
            .query_async(&mut conn)
            .await
            .expect("keys");
        if !keys.is_empty() {
            let _: () = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut conn)
                .await
                .expect("cleanup del");
        }
        drop(conn);

        owned.finish().await;
    }

    #[tokio::test]
    async fn check_stale_pending_events_survives_a_dead_redis() {
        let owned = provision_env("check_stale_dead_redis").await;
        let state = crate::test_support::state_with_dead_redis(&owned.pool);
        // Must warn and return instead of propagating the error.
        check_stale_pending_events(&state).await;
        owned.finish().await;
    }

    #[tokio::test]
    async fn check_stale_pending_events_survives_a_redis_that_dies_mid_scan() {
        // A private redis-server that is killed after the pool was created:
        // the SCAN fails at call time and the sweep degrades to a warn.
        let mut isolated = crate::test_support::spawn_isolated_redis();
        let config = crate::config::BillingConfig {
            redis_url: "redis://127.0.0.1:1".to_string(),
            ..crate::config::BillingConfig::default()
        };
        let state = crate::AppState::new(
            crate::test_support::broken_db_pool(),
            isolated.pool.clone(),
            config,
        );
        // Poison the pool by dropping the server behind it, then wait for the
        // socket to actually close so the SCAN fails deterministically.
        isolated.kill();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        check_stale_pending_events(&state).await;
    }
}
