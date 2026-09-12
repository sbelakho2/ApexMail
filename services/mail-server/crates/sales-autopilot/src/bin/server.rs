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
    dispatcher::ProductionCampaignDispatcher,
    enrichment::{EnrichmentService, HttpEnrichmentProvider},
    inbox::InboxManager,
    intelligence,
    knowledge::SalesKnowledgeBase,
    personalization::MessageStrategist,
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

    // Fail closed in production without a tenant allowlist (the internal
    // token is shared; unset meant every tenant was addressable).
    let is_production = std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(true);
    if let Err(reason) =
        sales_autopilot::config::require_tenant_allowlist_in_production(&cfg, is_production)
    {
        anyhow::bail!("refusing to start: {reason}");
    }
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
    let dispatcher: Option<Arc<ProductionCampaignDispatcher>> = if cfg.dispatch.is_configured() {
        // The SAME admission backend the REST and SMTP submission paths use:
        // sales quota/entitlement/suppression/category are enforced by the
        // one shared `SendAdmissionService` (audit implementation-order
        // item 3).
        match ProductionCampaignDispatcher::new(
            cfg.dispatch.clone(),
            db.clone(),
            Arc::new(
                billing_service::send_admission::PostgresAdmissionBackend::new(
                    db.clone(),
                    redis.clone(),
                ),
            ),
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

    // Captured before `dispatcher` is moved into the router state: the durable
    // action worker needs its own handle to the same dispatcher and pool.
    let dispatcher_for_worker = dispatcher.clone();
    let worker_db = db.clone();
    // The automation executor needs the SAME admission backend (db + redis)
    // the REST/SMTP/sales send paths use; `redis` is moved into AppState
    // below, so keep a handle here.
    let worker_redis = redis.clone();

    // The campaign manager is a compatibility planner only: `start_campaign`
    // adapts legacy campaign recipients into canonical contacts/sequence
    // enrollments. It owns no dispatcher and has no send path of its own.
    let campaigns = CampaignManager::new(cfg.max_campaigns, db.clone());

    // ── §12/§13 intelligence + strategist ─────────────────────────────
    // The live sequence planner owns the evidence-grounded stack: research,
    // angle selection and next-action reasoning go through the configured AI
    // provider (or the deterministic offline implementation when none is
    // configured), and prose is composed and claim-validated against the
    // canonical verified knowledge base. Constructed once and shared by the
    // router state and the durable action worker.
    let intelligence = intelligence::intelligence_from_env();
    let strategist = Arc::new(MessageStrategist::new(
        db.clone(),
        SalesKnowledgeBase::canonical(),
    ));
    let enrichment = EnrichmentService::new(Arc::new(HttpEnrichmentProvider::new(
        &cfg.enrichment_api_url,
        &cfg.enrichment_api_key,
    )));

    let state = AppState {
        config: cfg.clone(),
        enrichment: enrichment.clone(),
        campaigns,
        dispatcher: dispatcher.clone(),
        calendar: CalendarService::new(db.clone()),
        inbox: InboxManager::new(db.clone()),
        crm,
        redis,
        db,
        intelligence: intelligence.clone(),
        strategist: strategist.clone(),
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

    // The legacy campaign dispatch scheduler is GONE. There is no second send
    // loop: campaign mail is materialized into canonical enrollments by
    // `CampaignManager::start_campaign` and executed by the durable action
    // worker below (single send path, Decision Packet + legal + sender-health
    // + action fence applied). Do not re-add a campaign dispatch task here.

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

    // ── Durable sequence action worker ────────────────────────────────
    // The canonical execution loop: claim `sales_actions` rows with
    // FOR UPDATE SKIP LOCKED, run them through the sequence step handler, and
    // report an outcome. Any number of replicas may run this concurrently.
    //
    // The worker REQUIRES the production dispatcher. Starting it without one
    // would mean claiming real work and then having nothing to send it with,
    // so every claimed action would burn its attempt budget and dead-letter —
    // visible as data loss even though the queue itself was healthy. Without a
    // dispatcher the queue is left completely untouched and this is stated
    // loudly, both here and on the readiness surface.
    match dispatcher_for_worker {
        Some(dispatcher) => {
            let queue =
                sales_autopilot::actions::ActionQueue::new(worker_db.clone(), unique_worker_id());
            let handler: std::sync::Arc<dyn sales_autopilot::actions::ActionHandler> =
                std::sync::Arc::new(
                    sales_autopilot::sequence_worker::SequenceStepHandler::with_stack(
                        worker_db.clone(),
                        dispatcher,
                        intelligence,
                        strategist,
                    )
                    .with_enrichment(enrichment),
                );

            let mut worker_shutdown = shutdown_rx.clone();
            let interval = cfg.dispatch.dispatch_interval_secs.max(1);
            tokio::spawn(async move {
                sales_autopilot::actions::run(
                    queue,
                    handler,
                    interval,
                    ACTION_WORKER_CONCURRENCY,
                    sales_autopilot::actions::DEFAULT_LEASE_SECS,
                    async move {
                        let _ = worker_shutdown.changed().await;
                    },
                )
                .await;
            });
        }
        None => {
            tracing::warn!(
                "sales outbound action worker disabled: the production dispatcher is not \
                 configured (set SALES_CAMPAIGN_FROM_EMAIL and SALES_UNSUBSCRIBE_SECRET). \
                 Queued sales actions are left untouched so they are executed once a \
                 dispatcher is provisioned, rather than being claimed and dead-lettered."
            );
        }
    }

    // ── Sales feedback projector ──────────────────────────────────────
    // Folds the two delivery ledgers into the learning loops: sender-health
    // events into `sales_sender_health`, and production outcomes into the
    // experiment posteriors. Runs unconditionally — unlike the send worker it
    // has no dispatcher dependency, because it consumes events that were
    // already produced by whatever sent (or refused to send) the mail.
    {
        let projector = sales_autopilot::outcome_projector::OutcomeProjector::new(
            worker_db.clone(),
            unique_worker_id(),
        );
        let mut projector_shutdown = shutdown_rx.clone();
        let interval = cfg.dispatch.dispatch_interval_secs.max(1);
        tokio::spawn(async move {
            sales_autopilot::outcome_projector::run(
                projector,
                interval,
                OUTCOME_PROJECTOR_CONCURRENCY,
                sales_autopilot::actions::DEFAULT_LEASE_SECS,
                async move {
                    let _ = projector_shutdown.changed().await;
                },
            )
            .await;
        });
    }

    // ── Customer automation executor ──────────────────────────────────
    // The missing consumer of `automations.actions` (audit implementation-
    // order item 3). This host already owns the process's background work
    // (durable action worker + feedback projector) and is the crate that has
    // the executor, the pooled database and the shared
    // `PostgresAdmissionBackend`, so the tick is registered here with the same
    // shutdown watch as every other background job.
    //
    // Each tick claims a bounded batch of due trigger events with
    // FOR UPDATE SKIP LOCKED (migration 224), evaluates the tenant's enabled
    // rules and executes their actions; every send passes
    // `SendAdmissionService` — the ONE admission gate.
    {
        let admission = Arc::new(
            billing_service::send_admission::PostgresAdmissionBackend::new(
                worker_db.clone(),
                worker_redis,
            ),
        );
        let executor = Arc::new(sales_autopilot::automations::AutomationExecutor::new(
            worker_db.clone(),
            billing_service::send_admission::SendAdmissionService::new(admission),
            unique_worker_id(),
        ));
        let interval_secs = std::env::var("AUTOMATION_TICK_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(AUTOMATION_TICK_SECS_DEFAULT)
            .max(1);
        tracing::info!(
            interval_secs,
            batch = sales_autopilot::automations::DEFAULT_BATCH_SIZE,
            "automation executor started"
        );
        let mut automation_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match executor.tick().await {
                            Ok(report) if report.events_claimed > 0 => {
                                tracing::info!(
                                    events_claimed = report.events_claimed,
                                    events_processed = report.events_processed,
                                    events_deferred = report.events_deferred,
                                    runs_succeeded = report.runs_succeeded,
                                    runs_skipped = report.runs_skipped,
                                    runs_failed = report.runs_failed,
                                    actions_enqueued = report.actions_enqueued,
                                    "automation executor tick"
                                );
                            }
                            Ok(_) => {}
                            Err(error) => {
                                // The next tick retries; claim leases make a
                                // crash mid-tick a recoverable state.
                                tracing::error!(error = %error, "automation executor tick failed");
                            }
                        }
                    }
                    _ = automation_shutdown.changed() => break,
                }
            }
        });
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

/// Maximum actions this process runs simultaneously.
///
/// Bounded so a burst cannot open an unbounded number of concurrent sends;
/// the queue is claimed only up to the number of free slots.
const ACTION_WORKER_CONCURRENCY: i64 = 8;

/// Maximum feedback-projection batches in flight simultaneously.
const OUTCOME_PROJECTOR_CONCURRENCY: i64 = 4;

/// Default automation-executor tick period (seconds); `AUTOMATION_TICK_SECS`
/// overrides. A tick is cheap when there is no due work (one bounded claim
/// query + one bounded prune).
const AUTOMATION_TICK_SECS_DEFAULT: u64 = 30;

/// A worker identity that is unique per process across replicas.
///
/// The PID alone is not a valid replica identity — separate containers
/// routinely share the same PID number — so the hostname and a random suffix
/// are included. The lease token is what actually fences writes; this string
/// only makes the owner column diagnosable.
fn unique_worker_id() -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".into());
    format!("{}:{}:{}", host, std::process::id(), uuid::Uuid::new_v4())
}
