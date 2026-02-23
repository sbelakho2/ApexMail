use sales_autopilot::{
    calendar::CalendarService,
    campaigns::CampaignManager,
    config::SalesConfig,
    crm::CrmService,
    enrichment::EnrichmentService,
    inbox::InboxManager,
    routes::{self, AppState},
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialise structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let cfg = SalesConfig::from_env();
    tracing::info!(port = cfg.port, max_campaigns = cfg.max_campaigns, "starting sales-autopilot");

    let state = AppState {
        crm: CrmService::new(),
        enrichment: EnrichmentService::new(&cfg.enrichment_api_url),
        campaigns: CampaignManager::new(cfg.max_campaigns),
        calendar: CalendarService::new(),
        inbox: InboxManager::new(),
    };

    let app = routes::router(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!(addr = %addr, "listening");
    axum::serve(listener, app).await.unwrap();
}
