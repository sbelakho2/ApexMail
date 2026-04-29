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
        .context("DATABASE_URL environment variable must be set")?;
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&database_url)
        .await
        .context("Failed to connect to database")?;

    routes::initialize_schema(&db)
        .await
        .context("Failed to initialize sales-autopilot schema")?;

    let state = AppState {
        db,
        crm: CrmService::new(),
        enrichment: EnrichmentService::new(&cfg.enrichment_api_url),
        campaigns: CampaignManager::new(cfg.max_campaigns),
        calendar: CalendarService::new(),
        inbox: InboxManager::new(),
        service_token: {
            let token = std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default();
            if token.is_empty() {
                tracing::warn!("INTERNAL_SERVICE_TOKEN is not set — internal auth is effectively disabled");
            }
            token
        },
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
    let shutdown = async {
        let ctrl_c = async { let _ = tokio::signal::ctrl_c().await; };
        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            _ = ctrl_c => tracing::info!("received Ctrl+C — shutting down"),
            _ = terminate => tracing::info!("received SIGTERM — shutting down"),
        }
    };
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!(error = %err, "server error");
    }

    Ok(())
}
