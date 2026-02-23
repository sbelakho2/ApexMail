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

    // Connect to database
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .expect("failed to connect to database");

    let state = AppState {
        db: db.clone(),
        health: HealthChecker::new(1000),
        incidents: IncidentManager::new(db.clone()),
        slo: SloTracker::new(),
        warmup: IpWarmupManager::new(db),
    };

    // Load existing state from database
    if let Err(e) = state.incidents.load_from_db().await {
        tracing::warn!(?e, "Failed to load incidents from database");
    }
    if let Err(e) = state.warmup.load_from_db().await {
        tracing::warn!(?e, "Failed to load warmup schedules from database");
    }

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
