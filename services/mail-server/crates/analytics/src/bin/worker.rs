//! Analytics worker binary – standalone process with cron scheduling.

use clap::Parser;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = analytics::config::AnalyticsConfig::from_env();
    let args = Args::parse();

    info!("Starting analytics worker");

    // Database pool
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
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
        info!("Compaction result: migrated={}, bytes={}", result.rows_migrated, result.bytes_written);
        return Ok(());
    }

    if args.reconcile {
        let worker = analytics::reconciliation::ReconciliationWorker::new(pool.clone(), redis.clone());
        let result = worker.run().await?;
        info!("Reconciliation: found {} discrepancies", result.discrepancies_found);
        return Ok(());
    }

    if args.health {
        info!("Health check: OK");
        return Ok(());
    }

    // Main loop: schedule compaction + reconciliation + health checks
    let compaction_config = config.compaction.clone();
    let storage_path = config.storage_path.clone();
    let pool_c = pool.clone();
    let redis_c = redis.clone();
    let pool_r = pool.clone();
    let redis_r = redis.clone();

    // Compaction task (runs at configured hour, default 2 AM)
    let compaction_handle = tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now();
            let target_hour = compaction_config.schedule_hour;
            let next_run = next_scheduled_time(now, target_hour);
            let delay = (next_run - now).to_std().unwrap_or(std::time::Duration::from_secs(3600));

            info!("Next compaction in {}s", delay.as_secs());
            tokio::time::sleep(delay).await;

            if compaction_config.enabled {
                let worker = analytics::compaction::CompactionWorker::new(
                    pool_c.clone(),
                    redis_c.clone(),
                    compaction_config.clone(),
                    storage_path.clone(),
                );
                match worker.run().await {
                    Ok(result) => info!(
                        "Compaction complete: migrated={}, bytes={}",
                        result.rows_migrated, result.bytes_written
                    ),
                    Err(e) => error!("Compaction failed: {e}"),
                }
            }
        }
    });

    // Reconciliation task (runs at configured hour, default 3 AM)
    let reconciliation_config = config.reconciliation.clone();
    let reconciliation_handle = tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now();
            let target_hour = reconciliation_config.schedule_hour;
            let next_run = next_scheduled_time(now, target_hour);
            let delay = (next_run - now).to_std().unwrap_or(std::time::Duration::from_secs(3600));

            info!("Next reconciliation in {}s", delay.as_secs());
            tokio::time::sleep(delay).await;

            if reconciliation_config.enabled {
                let worker = analytics::reconciliation::ReconciliationWorker::new(
                    pool_r.clone(),
                    redis_r.clone(),
                );
                match worker.run().await {
                    Ok(result) => info!(
                        "Reconciliation: {} discrepancies found",
                        result.discrepancies_found
                    ),
                    Err(e) => error!("Reconciliation failed: {e}"),
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

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
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
