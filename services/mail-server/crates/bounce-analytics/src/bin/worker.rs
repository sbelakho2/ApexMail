//! Bounce analytics worker – runs periodic aggregation cycles.
//!
//! Usage:
//! ```bash
//! DATABASE_URL=postgres://... cargo run --bin bounce-analytics-worker
//! ```

use std::sync::Arc;
use std::time::Duration;

use bounce_analytics::aggregator::BounceAggregator;
use bounce_analytics::config::BounceAnalyticsConfig;
use clap::Parser;
use sqlx::PgPool;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "bounce-analytics-worker")]
struct Cli {
    /// Run once and exit (don't loop).
    #[arg(long)]
    once: bool,

    /// Override aggregation interval in seconds.
    #[arg(long, env = "BOUNCE_AGGREGATION_INTERVAL_SECS")]
    interval: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bounce_analytics=info,sqlx=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    dotenvy::dotenv().ok();

    let mut config = BounceAnalyticsConfig::from_env()?;
    if let Some(interval) = cli.interval {
        config.aggregation_interval_secs = interval;
    }

    info!(
        interval_secs = config.aggregation_interval_secs,
        window_days = config.aggregation_window_days,
        "Starting bounce analytics worker"
    );

    let pool = PgPool::connect(&config.database_url).await?;
    let aggregator = Arc::new(BounceAggregator::new(pool.clone(), config.clone()));

    // Initialize schema if needed
    aggregator.initialize_schema().await?;

    if cli.once {
        info!("Running single aggregation cycle");
        if let Err(e) = aggregator.run_aggregation().await {
            error!(error = %e, "Aggregation cycle failed");
        }
        info!("Done");
        return Ok(());
    }

    // Continuous loop
    loop {
        let start = std::time::Instant::now();

        if let Err(e) = aggregator.run_aggregation().await {
            error!(error = %e, "Aggregation cycle failed");
        }

        let elapsed = start.elapsed();
        let sleep_duration =
            Duration::from_secs(config.aggregation_interval_secs).saturating_sub(elapsed);

        info!(
            elapsed_ms = elapsed.as_millis(),
            sleep_secs = sleep_duration.as_secs(),
            "Aggregation cycle complete"
        );

        tokio::time::sleep(sleep_duration).await;
    }
}
