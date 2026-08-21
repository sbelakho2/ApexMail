use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use std::sync::Arc;

use anyhow::Context;
use sales_autopilot::{
    calendar::CalendarService,
    campaigns::CampaignManager,
    config::SalesConfig,
    crm::CrmBackend,
    dispatcher::{BillingQuotaGateway, ProductionCampaignDispatcher},
    enrichment::{EnrichmentService, HttpEnrichmentProvider},
    inbox::InboxManager,
    routes::{self, AppState},
};
use tracing_subscriber::EnvFilter;

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "sales-autopilot".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = init_tracing();

    let cfg = SalesConfig::from_env().context("failed to load sales-autopilot config")?;
    if cfg.enrichment_api_key.is_empty() {
        tracing::warn!(
            "ENRICHMENT_API_KEY is not set — enrichment requests will be unauthenticated and likely rejected by the provider"
        );
    }
    tracing::info!(
        port = cfg.port,
        max_campaigns = cfg.max_campaigns,
        "starting sales-autopilot"
    );

    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL environment variable must be set")?;
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

    // ── Redis pool (used for cross-process rate limiting) ──────────
    let redis = deadpool_redis::Config::from_url(&cfg.redis_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .context("Failed to create Redis pool")?;

    let crm = CrmBackend::postgres(db.clone());
    crm.initialize()
        .await
        .context("Failed to initialize CRM storage")?;

    // ── Production campaign dispatcher ────────────────────────────────
    // Configured (SALES_CAMPAIGN_FROM_EMAIL + SALES_UNSUBSCRIBE_SECRET)
    // ⇒ real sending through the platform pipeline. Unconfigured ⇒ None ⇒
    // campaign start keeps failing loudly with 503 (fix I-1 preserved).
    let dispatcher: Option<Arc<ProductionCampaignDispatcher>> =
        if cfg.dispatch.is_configured() {
            match ProductionCampaignDispatcher::new(
                cfg.dispatch.clone(),
                db.clone(),
                Arc::new(BillingQuotaGateway::new(db.clone(), redis.clone())),
            ) {
                Ok(d) => {
                    tracing::info!(
                        from_email = %d.config().from_email,
                        "production campaign dispatcher configured — campaigns will send through the platform pipeline"
                    );
                    Some(Arc::new(d))
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "invalid campaign dispatcher configuration — campaign start will return 503"
                    );
                    None
                }
            }
        } else {
            tracing::warn!(
                "campaign dispatcher NOT configured (set SALES_CAMPAIGN_FROM_EMAIL and \
                 SALES_UNSUBSCRIBE_SECRET to enable campaign sending) — campaign start returns 503"
            );
            None
        };

    let mut campaigns =
        CampaignManager::new(cfg.max_campaigns, db.clone())
            .with_dispatch_batch_size(cfg.dispatch.dispatch_batch_size);
    if let Some(ref d) = dispatcher {
        campaigns = campaigns
            .with_email_dispatcher(d.clone() as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>);
    }

    let state = AppState {
        config: cfg.clone(),
        enrichment: EnrichmentService::new(Arc::new(HttpEnrichmentProvider::new(
            &cfg.enrichment_api_url,
            &cfg.enrichment_api_key,
        ))),
        campaigns,
        dispatcher: dispatcher.clone(),
        calendar: CalendarService::new(db.clone()),
        inbox: InboxManager::new(db.clone()),
        crm,
        redis,
        db,
        service_token: {
            let token = std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default();
            if token.is_empty() {
                // An empty token would make require_service_token reject every
                // authenticated route — fail fast instead of starting a service
                // that can only serve /health.
                anyhow::bail!("INTERNAL_SERVICE_TOKEN must be set");
            }
            token
        },
        rate_limit_fallback: std::sync::Arc::new(parking_lot::Mutex::new(
            std::collections::HashMap::new(),
        )),
    };

    // Campaign dispatch scheduler: send due campaign batches every N seconds
    // (jittered), bounded per campaign and concurrency-bounded across
    // campaigns. Only runs when the production dispatcher is configured.
    // (Captured BEFORE `state` is moved into the router.)
    let scheduler_manager = dispatcher.as_ref().map(|_| state.campaigns.clone());

    let app = routes::router(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, addr = %addr, "failed to bind listener");
            return Err(anyhow::anyhow!("failed to bind {addr}: {err}"));
        }
    };
    tracing::info!(addr = %addr, "listening");

    // ── Background jobs ───────────────────────────────────────────────
    // Single shutdown broadcast: SIGTERM/Ctrl-C flips the watch; the axum
    // graceful-shutdown future AND every background job subscribe to it.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    tokio::spawn(async move {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            _ = ctrl_c => tracing::info!("received Ctrl+C — shutting down"),
            _ = terminate => tracing::info!("received SIGTERM — shutting down"),
        }
        let _ = shutdown_tx.send(());
    });

    if let Some(dispatcher) = dispatcher {
        if let Some(manager) = scheduler_manager {
            let mut scheduler_shutdown = shutdown_rx.clone();
            let interval = cfg.dispatch.dispatch_interval_secs;
            let batch = cfg.dispatch.dispatch_batch_size;
            let concurrency = cfg.dispatch.dispatch_concurrency;
            tokio::spawn(async move {
                sales_autopilot::scheduler::run(
                    manager,
                    dispatcher,
                    interval,
                    batch,
                    concurrency,
                    async move {
                        let _ = scheduler_shutdown.changed().await;
                    },
                )
                .await;
            });
        }
    }

    let mut server_shutdown = shutdown_rx.clone();
    let shutdown = async move {
        let _ = server_shutdown.changed().await;
    };
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!(error = %err, "server error");
        return Err(anyhow::anyhow!("server error: {err}"));
    }

    Ok(())
}
