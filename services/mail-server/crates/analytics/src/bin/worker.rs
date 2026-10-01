//! Analytics worker binary – standalone process with cron scheduling.

use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "analytics-worker", about = "ApexMail Analytics Worker")]
struct Args {
    /// Run compaction immediately and exit
    #[arg(long)]
    compact: bool,

    /// Run reconciliation immediately and exit
    #[arg(long)]
    reconcile: bool,

    /// Health check and exit
    #[arg(long)]
    health: bool,
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "analytics-worker".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let _guard = init_tracing();

    let config = analytics::config::AnalyticsConfig::from_env();
    // FINDING C (migration 231): state the cold-storage durability contract
    // at startup — the compaction ledger is the source of truth, the storage
    // root is a materialization and must be a durable mount (or backed by
    // object storage). Warning only; local dev is unaffected.
    analytics::config::warn_if_cold_storage_not_durable(&config.storage_path);
    let args = Args::parse();

    info!("Starting analytics worker");

    // Database pool
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&config.database_url)
        .await?;

    // Redis pool
    let redis_cfg = deadpool_redis::Config::from_url(&config.redis_url);
    let redis = redis_cfg
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .map_err(|e| anyhow::anyhow!("Redis pool error: {e}"))?;

    // One-shot modes
    if args.compact {
        let worker = analytics::compaction::CompactionWorker::new(
            pool.clone(),
            redis.clone(),
            config.compaction.clone(),
            config.storage_path.clone(),
        );
        let result = worker.run().await?;
        info!(
            "Compaction result: migrated={}, bytes={}",
            result.rows_migrated, result.bytes_written
        );
        return Ok(());
    }

    if args.reconcile {
        let worker =
            analytics::reconciliation::ReconciliationWorker::new(pool.clone(), redis.clone());
        let result = worker.run().await?;
        info!(
            "Reconciliation: found {} discrepancies",
            result.discrepancies_found
        );
        return Ok(());
    }

    if args.health {
        info!("Health check: OK");
        return Ok(());
    }

    // Main loop:schedule compaction + reconciliation + health checks
    let compaction_config = config.compaction.clone();
    let storage_path = config.storage_path.clone();
    let pool_c = pool.clone();
    let redis_c = redis.clone();
    let pool_r = pool.clone();
    let redis_r = redis.clone();

    // Compaction task (runs at configured hour, default 2 AM).
    // Failures retry in place under exponential backoff (M-48); the daily
    // scheduler is only re-entered after success or the retry cap (SM10 F10).
    let compaction_handle = tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now();
            let target_hour = compaction_config.schedule_hour;
            let next_run = next_scheduled_time(now, target_hour);
            let delay = (next_run - now)
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(3600));

            info!("Next compaction in {}s", delay.as_secs());
            tokio::time::sleep(delay).await;

            if compaction_config.enabled {
                let attempt = || {
                    let pool = pool_c.clone();
                    let redis = redis_c.clone();
                    let compaction_config = compaction_config.clone();
                    let storage_path = storage_path.clone();
                    async move {
                        analytics::compaction::CompactionWorker::new(
                            pool,
                            redis,
                            compaction_config,
                            storage_path,
                        )
                        .run()
                        .await
                    }
                };
                match run_scheduled_with_retry("compaction", attempt).await {
                    Ok(result) => {
                        info!(
                            "Compaction complete: migrated={}, bytes={}",
                            result.rows_migrated, result.bytes_written
                        );
                    }
                    Err(e) => {
                        error!("Compaction failed after all in-place retries; handing back to the scheduler: {e}");
                    }
                }
            }
        }
    });

    // Reconciliation task (runs at configured hour, default 3 AM).
    // Same in-place retry contract as compaction (M-48 + SM10 F10).
    let reconciliation_config = config.reconciliation.clone();
    let reconciliation_handle = tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now();
            let target_hour = reconciliation_config.schedule_hour;
            let next_run = next_scheduled_time(now, target_hour);
            let delay = (next_run - now)
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(3600));

            info!("Next reconciliation in {}s", delay.as_secs());
            tokio::time::sleep(delay).await;

            if reconciliation_config.enabled {
                let attempt = || {
                    let pool = pool_r.clone();
                    let redis = redis_r.clone();
                    async move {
                        analytics::reconciliation::ReconciliationWorker::new(pool, redis)
                            .run()
                            .await
                    }
                };
                match run_scheduled_with_retry("reconciliation", attempt).await {
                    Ok(result) => {
                        info!(
                            "Reconciliation: {} discrepancies found",
                            result.discrepancies_found
                        );
                    }
                    Err(e) => {
                        error!("Reconciliation failed after all in-place retries; handing back to the scheduler: {e}");
                    }
                }
            }
        }
    });

    // Health check (every 60s)
    let health_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            // Simple ping check
            match sqlx::query("SELECT 1").fetch_one(&pool).await {
                Ok(_) => {}
                Err(e) => error!("Health check failed: {e}"),
            }
        }
    });

    // Wait for shutdown signal (SIGINT or SIGTERM)
    {
        let ctrl_c = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => info!("received Ctrl+C"),
                Err(e) => {
                    error!("failed to install Ctrl+C handler: {e}");
                    std::future::pending::<()>().await;
                }
            }
        };
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => tokio::select! {
                    _ = ctrl_c => {}
                    _ = terminate.recv() => info!("received SIGTERM"),
                },
                Err(e) => {
                    error!("failed to install SIGTERM handler: {e}; falling back to Ctrl+C only");
                    ctrl_c.await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await;
        }
    }
    info!("Shutting down analytics worker");

    compaction_handle.abort();
    reconciliation_handle.abort();
    health_handle.abort();

    Ok(())
}

/// Calculate next occurrence of a specific UTC hour.
fn next_scheduled_time(
    now: chrono::DateTime<chrono::Utc>,
    target_hour: u32,
) -> chrono::DateTime<chrono::Utc> {
    use chrono::{TimeDelta, Timelike};

    let current_hour = now.hour();
    let hours_until = if current_hour < target_hour {
        target_hour - current_hour
    } else {
        24 - current_hour + target_hour
    };

    now + TimeDelta::try_hours(hours_until as i64).unwrap_or(TimeDelta::zero())
        - TimeDelta::try_minutes(now.minute() as i64).unwrap_or(TimeDelta::zero())
        - TimeDelta::try_seconds(now.second() as i64).unwrap_or(TimeDelta::zero())
}

/// Backoff before the next retry after a scheduled task failure (M-48):
/// the wait doubles per consecutive failure, capped at one hour, so a
/// persisted outage must degrade into slow retries instead of a tight loop.
fn backoff_after_failure(current_backoff_secs: u64) -> u64 {
    const MAX_BACKOFF_SECS: u64 = 3600; // 1 hour cap
    (current_backoff_secs * 2).min(MAX_BACKOFF_SECS)
}

/// First in-place retry wait after a scheduled run failed.
const INITIAL_TASK_BACKOFF_SECS: u64 = 30;
/// In-place retries allowed after the initial failure before a scheduled
/// slot gives up and hands back to the daily scheduler (SM10 F10). Five
/// retries under the doubling backoff span ~15.5 minutes — long enough to
/// ride out a DB/Redis blip, short enough that a failed nightly compaction
/// never waits a full day to run while the hot `events` table keeps growing.
const MAX_TASK_RETRIES: u32 = 5;

/// Run one scheduled task with IN-PLACE retries (SM10 F10).
///
/// The nightly loops used to `continue` back into the scheduler on failure,
/// whose first act was recomputing `next_scheduled_time` → tomorrow — so the
/// exponential backoff was dead in effect and a failed run was retried at
/// most once per day. This helper retries the task DIRECTLY (attempt, then
/// up to [`MAX_TASK_RETRIES`] retries under [`backoff_after_failure`]) and
/// only returns to the scheduler after success or retry exhaustion.
async fn run_scheduled_with_retry<T, E, F, Fut>(task_name: &str, mut task: F) -> Result<T, E>
where
    E: std::fmt::Display,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut result = task().await;
    if result.is_ok() {
        return result;
    }

    let mut backoff = INITIAL_TASK_BACKOFF_SECS;
    for retry in 1..=MAX_TASK_RETRIES {
        error!(
            task = task_name,
            retry,
            max_retries = MAX_TASK_RETRIES,
            backoff_secs = backoff,
            "scheduled task failed; retrying in place"
        );
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = backoff_after_failure(backoff);
        result = task().await;
        if result.is_ok() {
            return result;
        }
    }

    error!(
        task = task_name,
        retries = MAX_TASK_RETRIES,
        "scheduled task still failing after all in-place retries"
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    // ── next_scheduled_time: the scheduler's clock arithmetic ──────────

    #[test]
    fn schedules_at_the_target_hour_later_today() {
        // 01:15:30 with a 02:00 target → today 02:00:00.
        let now = Utc.with_ymd_and_hms(2026, 9, 21, 1, 15, 30).unwrap();
        let next = next_scheduled_time(now, 2);
        assert_eq!(
            next,
            Utc.with_ymd_and_hms(2026, 9, 21, 2, 0, 0).unwrap(),
            "minutes and seconds must be truncated away"
        );
    }

    #[test]
    fn schedules_tomorrow_when_the_target_hour_already_passed() {
        let now = Utc.with_ymd_and_hms(2026, 9, 21, 4, 0, 1).unwrap();
        let next = next_scheduled_time(now, 2);
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 9, 22, 2, 0, 0).unwrap());
    }

    #[test]
    fn schedules_exactly_one_day_out_when_running_at_the_target_hour() {
        // The tick that fires at 02:00:00 must not schedule 0s ahead.
        let now = Utc.with_ymd_and_hms(2026, 9, 21, 2, 0, 0).unwrap();
        let next = next_scheduled_time(now, 2);
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 9, 22, 2, 0, 0).unwrap());
    }

    #[test]
    fn handles_the_last_hour_of_the_day() {
        // 23:xx with a 02:00 target crosses midnight: 24 - 23 + 2 = 3h.
        let now = Utc.with_ymd_and_hms(2026, 9, 21, 23, 59, 59).unwrap();
        let next = next_scheduled_time(now, 2);
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 9, 22, 2, 0, 0).unwrap());
    }

    #[test]
    fn handles_hour_zero_target() {
        let now = Utc.with_ymd_and_hms(2026, 9, 21, 13, 45, 10).unwrap();
        let next = next_scheduled_time(now, 0);
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 9, 22, 0, 0, 0).unwrap());
    }

    #[test]
    fn always_schedules_at_least_seconds_into_the_future() {
        // Sub-minute times are truncated: the delay is never negative, and
        // a within-the-target-hour run lands on the next day's slot.
        for hour in 0..24u32 {
            let now = Utc.with_ymd_and_hms(2026, 9, 21, hour, 59, 59).unwrap();
            let next = next_scheduled_time(now, hour);
            assert!(
                next > now,
                "hour {hour}: the next run must be in the future (next={next}, now={now})"
            );
        }
    }

    // ── backoff_after_failure: the M-48 no-tight-loop contract ─────────

    #[test]
    fn backoff_doubles_and_caps_at_one_hour() {
        let mut backoff = 30;
        let mut seen = vec![backoff];
        for _ in 0..8 {
            backoff = backoff_after_failure(backoff);
            seen.push(backoff);
        }
        assert_eq!(seen, vec![30, 60, 120, 240, 480, 960, 1920, 3600, 3600]);
    }

    // ── run_scheduled_with_retry: the SM10 F10 in-place retry contract ────

    /// A success on the first attempt must go straight back to the
    /// scheduler: exactly one attempt, no retry sleeps.
    #[tokio::test(start_paused = true)]
    async fn retry_helper_returns_to_scheduler_after_first_try_success() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<&str, String> = run_scheduled_with_retry("ok-first-try", || {
            let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if n == 0 {
                    Ok("done")
                } else {
                    Err("must not be re-attempted".to_string())
                }
            }
        })
        .await;
        assert_eq!(result, Ok("done"));
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a first-try success must not be retried"
        );
    }

    /// THE F10 regression: a failure must re-attempt the task DIRECTLY (not
    /// hand back to the daily scheduler) until it succeeds — the old loop's
    /// `continue` re-entered the scheduler, which slept ~24 h before the
    /// "retry", rendering the backoff dead.
    #[tokio::test(start_paused = true)]
    async fn retry_helper_re_attempts_in_place_until_success() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<(), String> = run_scheduled_with_retry("flaky", || {
            let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if n < 3 {
                    Err(format!("transient failure {n}"))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "one initial attempt plus in-place retries — never a scheduler round-trip"
        );
    }

    /// Retry exhaustion: after the cap the helper gives the slot back to the
    /// scheduler with the last error instead of retrying forever.
    #[tokio::test(start_paused = true)]
    async fn retry_helper_hands_back_to_scheduler_after_the_cap() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<(), String> = run_scheduled_with_retry("dead", || {
            let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { Err(format!("permanent failure after attempt {n}")) }
        })
        .await;
        assert!(result.is_err(), "exhausted retries surface the last error");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1 + MAX_TASK_RETRIES as usize,
            "exactly the initial attempt plus MAX_TASK_RETRIES retries"
        );
    }

    /// The retry waits honor the same exponential backoff ladder the M-48
    /// cap test pins: sleeps observed on a paused clock total the ladder
    /// sum, proving no rung was skipped or repeated.
    #[tokio::test(start_paused = true)]
    async fn retry_helper_sleeps_the_backoff_ladder_between_attempts() {
        let expected: u64 = (0..MAX_TASK_RETRIES)
            .scan(INITIAL_TASK_BACKOFF_SECS, |acc, _| {
                let cur = *acc;
                *acc = backoff_after_failure(*acc);
                Some(cur)
            })
            .sum();
        let started = tokio::time::Instant::now();
        let _ = run_scheduled_with_retry::<(), String, _, _>("timed", || async move {
            Err("always fails".to_string())
        })
        .await;
        let elapsed = started.elapsed();
        assert_eq!(
            elapsed,
            std::time::Duration::from_secs(expected),
            "the in-place retries must sleep exactly the M-48 backoff ladder"
        );
    }
}
