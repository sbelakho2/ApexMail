use sales_autopilot::{
    calendar::CalendarService,
    campaigns::CampaignManager,
    config::SalesConfig,
    crm::CrmService,
    enrichment::EnrichmentService,
    inbox::InboxManager,
    routes::{self, AppState},
};
use anyhow::Context;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let cfg = SalesConfig::from_env();
    tracing::info!(port = cfg.port, max_campaigns = cfg.max_campaigns, "starting sales-autopilot");

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/apexmail".into());
    let db = sqlx::PgPool::connect(&database_url)
        .await
        .context("Failed to connect to database")?;

    let state = AppState {
        db,
        crm: CrmService::new(),
        enrichment: EnrichmentService::new(&cfg.enrichment_api_url),
        campaigns: CampaignManager::new(cfg.max_campaigns),
        calendar: CalendarService::new(),
        inbox: InboxManager::new(),
    };

    let app = routes::router(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, addr = %addr, "failed to bind listener");
            return Ok(());
        }
    };
    tracing::info!(addr = %addr, "listening");
    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(error = %err, "server error");
    }

    Ok(())
}
