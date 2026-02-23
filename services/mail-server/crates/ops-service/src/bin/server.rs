//! Entry point for the ops-service binary.

use ops_service::config::OpsConfig;
use ops_service::health::HealthChecker;
use ops_service::incidents::IncidentManager;
use ops_service::routes::{router, AppState};
use ops_service::slo::SloTracker;
use ops_service::warmup::IpWarmupManager;
use tracing::info;

#[tokio::main]
async fn main() {
    // Initialise tracing
    tracing_subscriber::fmt::init();

    let config = OpsConfig::from_env();
    info!(?config, "ops-service starting");

    let state = AppState {
        health: HealthChecker::new(1000),
        incidents: IncidentManager::new(),
        slo: SloTracker::new(),
        warmup: IpWarmupManager::new(),
    };

    let app = router(state);

    let addr = format!("0.0.0.0:{}", config.port);
    info!(addr, "listening");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind TCP listener");

    axum::serve(listener, app)
        .await
        .expect("server error");
}
