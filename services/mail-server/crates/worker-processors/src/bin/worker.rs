//! Worker entry point — runs all processors.

use std::collections::HashSet;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use axum::{http::header::CONTENT_TYPE, response::IntoResponse, routing::get, Router};
use deadpool_redis::{Config as RedisConfig, Runtime};
use metrics_exporter_prometheus::PrometheusBuilder;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use worker_processors::{
    common::{
        AnalyticsConfig, DkimConfig, EmailConfig, ProcessorConfig, ReplyHandlerConfig, SesConfig,
        SmtpConfig, TrackingConfig, TransportType, WebhookConfig,
    },
    AnalyticsProcessor, EmailProcessor, ReplyHandler, WebhookProcessor,
};

/// Registry of which supervised processors are currently alive.
///
/// The heartbeat consults it on every beat so a processor that panicked (or
/// is sitting in its restart backoff) stops being advertised to the control
/// plane until it lives again. SM10 F1: the heartbeat used to advertise a
/// static capability list, so a worker whose email processor had panicked
/// kept reporting a healthy, email-capable worker while delivering nothing.
#[derive(Clone, Default)]
struct ProcessorLiveness {
    alive: Arc<Mutex<HashSet<&'static str>>>,
}

impl ProcessorLiveness {
    fn new() -> Self {
        Self::default()
    }

    fn set_alive(&self, name: &'static str, alive: bool) {
        let mut guard = self.alive.lock().unwrap_or_else(|e| e.into_inner());
        if alive {
            guard.insert(name);
        } else {
            guard.remove(name);
        }
    }

    fn is_alive(&self, name: &str) -> bool {
        self.alive
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(name)
    }
}

/// Supervise a processor: restart it with capped exponential backoff whenever
/// the attempt exits, either through an `Err` return or through a PANIC.
/// `Ok(())` is a clean shutdown (Ctrl+C path) and ends supervision.
///
/// Each attempt runs in its own tokio task and supervision awaits that task's
/// `JoinHandle` for the entire attempt lifetime, so a panic surfaces as
/// `JoinError::is_panic` instead of unwinding through (and killing) the
/// supervisor itself. SM10 F1: the previous supervision only matched
/// `Err` — a panic permanently killed the processor while the heartbeat,
/// `/health`, and `/metrics` all stayed green, so Kubernetes saw a healthy
/// worker delivering nothing. On panic the processor is logged dead, the
/// `apexmail_processor_alive` gauge drops to 0, and the heartbeat capability
/// entry is withheld until the restarted attempt is running again.
async fn supervise<F, Fut>(name: &'static str, liveness: ProcessorLiveness, mut start: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = worker_processors::ProcessorResult<()>> + Send + 'static,
{
    let mut backoff_secs: u64 = 5;
    loop {
        liveness.set_alive(name, true);
        metrics::gauge!("apexmail_processor_alive", "processor" => name).set(1.0);

        let attempt = tokio::spawn(start());
        match attempt.await {
            Ok(Ok(())) => {
                mark_dead(&liveness, name);
                info!(processor = name, "processor shut down cleanly");
                return;
            }
            Ok(Err(e)) => {
                error!(
                    processor = name,
                    error = %e,
                    backoff_secs,
                    "processor failed; restarting under supervision"
                );
            }
            Err(join_error) if join_error.is_panic() => {
                metrics::counter!("apexmail_processor_panics_total", "processor" => name)
                    .increment(1);
                let payload = join_error.into_panic();
                let message = payload
                    .downcast_ref::<&'static str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<opaque panic payload>".to_string());
                error!(
                    processor = name,
                    panic = %message,
                    backoff_secs,
                    "processor PANICKED; restarting under supervision"
                );
            }
            Err(join_error) => {
                error!(
                    processor = name,
                    error = %join_error,
                    backoff_secs,
                    "processor task was cancelled; restarting under supervision"
                );
            }
        }

        // Dead between attempts: drop the liveness registration and gauge for
        // the backoff window — both are restored when the attempt respawns.
        mark_dead(&liveness, name);
        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    }
}

/// Record a processor as not-running: clear the heartbeat liveness entry and
/// drop the per-processor gauge so scrapes see the outage.
fn mark_dead(liveness: &ProcessorLiveness, name: &'static str) {
    liveness.set_alive(name, false);
    metrics::gauge!("apexmail_processor_alive", "processor" => name).set(0.0);
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "worker".to_string(),
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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    None
}

/// Environment-resolved startup settings (concurrency, poll cadence, which
/// processors run). Extracted from `main` so every parse arm is testable.
#[derive(Debug, Clone, Copy)]
struct WorkerSettings {
    concurrency: usize,
    poll_interval: Duration,
    run_analytics: bool,
    run_email: bool,
    run_reply_handler: bool,
    run_webhook: bool,
    run_automations: bool,
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true)
}

fn load_worker_settings() -> WorkerSettings {
    let concurrency: usize = env::var("WORKER_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
        .max(1);

    let poll_interval = Duration::from_secs(
        env::var("WORKER_POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5),
    );

    WorkerSettings {
        concurrency,
        poll_interval,
        run_analytics: env_flag("WORKER_RUN_ANALYTICS"),
        run_email: env_flag("WORKER_RUN_EMAIL"),
        run_reply_handler: env_flag("WORKER_RUN_REPLY_HANDLER"),
        run_webhook: env_flag("WORKER_RUN_WEBHOOK"),
        run_automations: env_flag("WORKER_RUN_AUTOMATIONS"),
    }
}

/// Default automation-executor tick period (seconds); `AUTOMATION_TICK_SECS`
/// overrides. A tick is cheap when there is no due work (one bounded claim
/// query + one bounded prune).
const AUTOMATION_TICK_SECS_DEFAULT: u64 = 30;

/// Tick period for the customer automation executor (`AUTOMATION_TICK_SECS`),
/// clamped to at least one second; a present-but-invalid value falls back to
/// the default (the executor is background work — a hostile cadence must not
/// stop the worker from starting).
fn automation_tick_secs() -> u64 {
    env::var("AUTOMATION_TICK_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(AUTOMATION_TICK_SECS_DEFAULT)
        .max(1)
}

/// Capabilities advertised on the worker heartbeat: the infrastructure
/// always present, each enabled SUPERVISED processor only while supervision
/// has it alive (SM10 F1 — a panicked/dead processor must stop being
/// advertised), and the automation tick whenever enabled (its self-contained
/// loop handles its own errors and is not supervised).
fn heartbeat_capabilities(settings: &WorkerSettings, liveness: &ProcessorLiveness) -> Vec<String> {
    let mut capabilities = vec!["postgres".to_string(), "redis".to_string()];
    let supervised: &[(&'static str, bool)] = &[
        ("analytics", settings.run_analytics),
        ("email", settings.run_email),
        ("reply-handler", settings.run_reply_handler),
        ("webhook", settings.run_webhook),
    ];
    for (name, enabled) in supervised {
        if *enabled && liveness.is_alive(name) {
            capabilities.push((*name).to_string());
        }
    }
    if settings.run_automations {
        capabilities.push("automations".to_string());
    }
    capabilities
}

/// Spawn the worker heartbeat emitter.
///
/// Unlike the library's `spawn_service_heartbeat` (which beats a STATIC
/// capability list), the capability list is recomputed from the liveness
/// registry on EVERY beat, so a processor that panicked or is in its restart
/// backoff disappears from the control plane until it lives again. The beat
/// contract is otherwise identical: first beat immediately, failures are
/// logged and never fatal.
fn spawn_liveness_heartbeat(
    db: sqlx::PgPool,
    settings: WorkerSettings,
    liveness: ProcessorLiveness,
    mut config: apexmail_lib::heartbeat::HeartbeatConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(config.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            config.capabilities = heartbeat_capabilities(&settings, &liveness);
            match apexmail_lib::heartbeat::record_heartbeat(&db, &config).await {
                Ok(()) => tracing::trace!(
                    service = %config.service,
                    instance_id = %config.instance_id,
                    "worker heartbeat recorded"
                ),
                Err(error) => tracing::warn!(
                    service = %config.service,
                    instance_id = %config.instance_id,
                    error = %error,
                    "worker heartbeat failed (will retry on the next beat)"
                ),
            }
        }
    })
}

/// VERP v2 secret requirement (mirrors the MTA's production gate): outbound
/// mail may only carry an AUTHENTICATED bounce Return-Path. Without the
/// shared secret the worker emits NO VERP at all — it never falls back to
/// the unsigned v1 grammar — and production startup refuses the
/// configuration when the email processor is enabled.
fn verp_secret_gate(run_email: bool) -> Result<()> {
    let verp_domain_enabled = env::var("VERP_DOMAIN")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(true);
    let verp_secret_ok = env::var("VERP_HMAC_SECRET")
        .map(|v| v.trim().len() >= apexmail_lib::verp::VERP_V2_MIN_SECRET_LEN)
        .unwrap_or(false);
    if verp_domain_enabled && !verp_secret_ok {
        let production = env::var("NODE_ENV")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "production" | "prod"
                )
            })
            .unwrap_or(false);
        if production && run_email {
            anyhow::bail!(
                "VERP_HMAC_SECRET must be set (>= {} bytes) when running the email processor in \
                 production: unsigned v1 VERP is no longer emitted and bounces cannot be \
                 authenticated without the shared secret",
                apexmail_lib::verp::VERP_V2_MIN_SECRET_LEN
            );
        }
        warn!(
            "VERP_HMAC_SECRET is unset or shorter than {} bytes: outbound mail will carry NO \
             VERP Return-Path (unsigned v1 is not emitted); set the shared secret to enable \
             authenticated bounce routing",
            apexmail_lib::verp::VERP_V2_MIN_SECRET_LEN
        );
    }
    Ok(())
}

/// Create the Postgres pool with the production tunings (PERF-116: 60s
/// acquire timeout, statement cache capacity 100).
async fn connect_db(database_url: &str) -> Result<sqlx::PgPool> {
    let connect_opts = database_url
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .statement_cache_capacity(100);
    let db = PgPoolOptions::new()
        .max_connections(30)
        .acquire_timeout(Duration::from_secs(60))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .connect_with(connect_opts)
        .await?;
    Ok(db)
}

/// Create the Redis pool from a URL.
fn connect_redis(redis_url: &str) -> Result<deadpool_redis::Pool> {
    let redis_cfg = RedisConfig::from_url(redis_url);
    Ok(redis_cfg.create_pool(Some(Runtime::Tokio1))?)
}

/// Resolve the SMTP relay host. Only `smtp` selects SMTP; SES is the default
/// for every other value. An empty/missing SMTP_HOST is fatal ONLY for the
/// SMTP transport — with SES the deliberately invalid sentinel host stays in
/// place so the hybrid dispatcher knows the relay is NOT configured and
/// dedicated-route sends defer before DATA instead of routing at localhost.
fn smtp_host_for(transport_type: &TransportType) -> Result<String> {
    match env::var("SMTP_HOST") {
        Ok(h) if !h.is_empty() => Ok(h),
        Ok(_) | Err(_) => {
            if *transport_type == TransportType::Smtp {
                anyhow::bail!(
                    "SMTP_HOST environment variable must be set when EMAIL_TRANSPORT_TYPE=smtp"
                );
            }
            warn!(
                "SMTP_HOST not set; SES shared-pool transport selected — dedicated \
                 delivery routes (dedicated_ips rows) will defer until a relay is configured"
            );
            Ok(SmtpConfig::default().host)
        }
    }
}

/// Build the email processor configuration from the environment.
fn build_email_config(concurrency: usize, poll_interval: Duration) -> Result<EmailConfig> {
    // Choose transport backend via EMAIL_TRANSPORT_TYPE env var.
    let transport_type = env::var("EMAIL_TRANSPORT_TYPE")
        .map(|v| TransportType::from_env(&v))
        .unwrap_or_default();

    let smtp_host = smtp_host_for(&transport_type)?;

    let smtp_config = SmtpConfig {
        host: smtp_host,
        port: env::var("SMTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(587),
        secure: env::var("SMTP_TLS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(true),
        username: env::var("SMTP_USERNAME").ok().filter(|s| !s.is_empty()),
        password: env::var("SMTP_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty())
            .map(zeroize::Zeroizing::new),
        ..Default::default()
    };
    let ses_config = SesConfig {
        // Keep this default aligned with api-server's Config::from_env.
        // Production compose passes AWS_REGION explicitly to both
        // services; this fallback only protects local/test deployments.
        region: env::var("AWS_REGION")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "us-east-1".to_string()),
        configuration_set: env::var("SES_CONFIGURATION_SET")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        ..Default::default()
    };

    Ok(EmailConfig {
        base: ProcessorConfig {
            name: "email".to_string(),
            concurrency,
            poll_interval,
            ..Default::default()
        },
        transport_type,
        smtp: smtp_config,
        ses: ses_config,
        dkim: DkimConfig {
            enabled: env::var("DKIM_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            // Customer-domain selectors and keys are retrieved from the
            // encrypted domains table per job. Do not load one global key
            // that could sign another tenant's domain.
            ..Default::default()
        },
        // Tracking enablement is env-driven (TRACKING_ENABLED +
        // TRACKING_SECRET_KEY): previously the ..Default::default() here
        // always left `enabled: false`, so pixels/links were never
        // rewritten and engagement accounting was dead.
        tracking: TrackingConfig::from_env(),
        ..Default::default()
    })
}

/// A base `ProcessorConfig` for a named processor.
fn base_config(name: &str, settings: &WorkerSettings) -> ProcessorConfig {
    ProcessorConfig {
        name: name.to_string(),
        concurrency: settings.concurrency,
        poll_interval: settings.poll_interval,
        ..Default::default()
    }
}

/// Everything `run_worker` starts, so tests (and the shutdown path) can stop
/// it deterministically.
struct WorkerProcesses {
    handles: Vec<tokio::task::JoinHandle<()>>,
    analytics: Option<Arc<AnalyticsProcessor>>,
    email: Option<Arc<EmailProcessor>>,
    reply: Option<Arc<ReplyHandler>>,
    webhook: Option<Arc<WebhookProcessor>>,
    /// The customer automation executor's tick task. Unlike the processors
    /// above it is a self-contained loop (no `stop()` handshake): shutdown
    /// aborts it at its next await point, which is safe because every claim
    /// it holds is leased and every write exactly-once (migration 224), so an
    /// aborted tick is recovered by a later one, never double-executed.
    automations: Option<tokio::task::JoinHandle<()>>,
    heartbeat: tokio::task::JoinHandle<()>,
}

/// Start every enabled processor against INJECTED pools plus the heartbeat
/// emitter. Supervised: each processor restarts with capped backoff on error.
async fn run_worker(
    db: sqlx::PgPool,
    redis: deadpool_redis::Pool,
    settings: &WorkerSettings,
) -> Result<WorkerProcesses> {
    // ── Process heartbeat (real liveness for the control plane) ──
    // system_health reads service_heartbeats; queue activity is NOT a
    // liveness signal. Capabilities list the processors this process runs —
    // filtered per beat by SUPERVISION LIVENESS so a panicked processor
    // stops being advertised (SM10 F1). Beats start immediately; failures
    // are logged, never fatal.
    let liveness = ProcessorLiveness::new();
    let heartbeat_config =
        apexmail_lib::heartbeat::HeartbeatConfig::new("worker", env!("CARGO_PKG_VERSION"))
            .with_interval_from_env()
            .with_region_from_env();
    info!(
        instance_id = %heartbeat_config.instance_id,
        "worker heartbeat emitter started"
    );
    let heartbeat =
        spawn_liveness_heartbeat(db.clone(), *settings, liveness.clone(), heartbeat_config);

    // ── Automatic warmup graduation (P1) ──
    // Idempotent reconciler: warming → active at the canonical 60-day term.
    // Runs on an hourly cadence; each pass is a no-op unless an IP matured.
    {
        let db = db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match worker_processors::common::graduation::graduate_mature_warmup_ips(&db).await {
                    Ok(graduated) if !graduated.is_empty() => {
                        tracing::info!(count = graduated.len(), "warmup graduation reconciler ran")
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!(%error, "warmup graduation reconciler failed")
                    }
                }
            }
        });
    }

    verp_secret_gate(settings.run_email)?;

    let mut handles = vec![];
    let mut analytics_processor: Option<Arc<AnalyticsProcessor>> = None;
    let mut email_processor: Option<Arc<EmailProcessor>> = None;
    let mut reply_processor: Option<Arc<ReplyHandler>> = None;
    let mut webhook_processor: Option<Arc<WebhookProcessor>> = None;
    let mut automations_task: Option<tokio::task::JoinHandle<()>> = None;

    // Start analytics processor
    if settings.run_analytics {
        let config = AnalyticsConfig {
            base: base_config("analytics", settings),
            ..Default::default()
        };

        let processor = Arc::new(AnalyticsProcessor::new(db.clone(), redis.clone(), config));
        let p = Arc::clone(&processor);
        let liveness = liveness.clone();
        handles.push(tokio::spawn(async move {
            supervise("analytics", liveness, move || {
                let p = Arc::clone(&p);
                async move { p.start().await }
            })
            .await;
        }));
        analytics_processor = Some(processor);
        info!("Analytics processor started");
    }

    // Start email processor
    if settings.run_email {
        let config = build_email_config(settings.concurrency, settings.poll_interval)?;
        info!(transport = ?config.transport_type, "Email transport backend selected");

        match EmailProcessor::new(db.clone(), redis.clone(), config).await {
            Ok(processor) => {
                let processor = Arc::new(processor);
                let p = Arc::clone(&processor);
                let liveness = liveness.clone();
                handles.push(tokio::spawn(async move {
                    supervise("email", liveness, move || {
                        let p = Arc::clone(&p);
                        async move { p.start().await }
                    })
                    .await;
                }));
                email_processor = Some(processor);
                info!("Email processor started");
            }
            Err(e) => {
                error!(error = %e, "Failed to create email processor");
            }
        }
    }

    // Start reply handler
    if settings.run_reply_handler {
        let config = ReplyHandlerConfig {
            base: base_config("reply-handler", settings),
            ..Default::default()
        };

        let processor = Arc::new(ReplyHandler::new(db.clone(), config));
        let p = Arc::clone(&processor);
        let liveness = liveness.clone();
        handles.push(tokio::spawn(async move {
            supervise("reply-handler", liveness, move || {
                let p = Arc::clone(&p);
                async move { p.start().await }
            })
            .await;
        }));
        reply_processor = Some(processor);
        info!("Reply handler started");
    }

    // Start webhook processor
    if settings.run_webhook {
        let config = WebhookConfig {
            base: base_config("webhook", settings),
            ..Default::default()
        };

        match WebhookProcessor::new(db.clone(), redis.clone(), config) {
            Ok(processor) => {
                let processor = Arc::new(processor);
                let p = Arc::clone(&processor);
                let liveness = liveness.clone();
                handles.push(tokio::spawn(async move {
                    supervise("webhook", liveness, move || {
                        let p = Arc::clone(&p);
                        async move { p.start().await }
                    })
                    .await;
                }));
                webhook_processor = Some(processor);
                info!("Webhook processor started");
            }
            Err(e) => {
                error!(error = %e, "Failed to create webhook processor");
            }
        }
    }

    // ── Customer automation executor (moved from sales-autopilot) ─────
    // The consumer of `automation_trigger_events` (migration 224): each tick
    // claims a bounded batch of due trigger events with FOR UPDATE SKIP
    // LOCKED, evaluates the tenant's enabled rules and executes their action
    // ladder; every send passes `SendAdmissionService` — the ONE admission
    // gate. This is CUSTOMER automation: it runs in the worker fleet, not in
    // the owner-only sales-autopilot process, so the two trust domains stay
    // separable (the sales brain can be disabled without touching customer
    // automations and vice versa).
    if settings.run_automations {
        let admission = Arc::new(
            billing_service::send_admission::PostgresAdmissionBackend::new(
                db.clone(),
                redis.clone(),
            ),
        );
        let executor = Arc::new(worker_processors::automations::AutomationExecutor::new(
            db.clone(),
            billing_service::send_admission::SendAdmissionService::new(admission),
            unique_worker_id(),
        ));
        let interval_secs = automation_tick_secs();
        info!(
            interval_secs,
            batch = worker_processors::automations::DEFAULT_BATCH_SIZE,
            "Automation executor started"
        );
        automations_task = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match executor.tick().await {
                    Ok(report) if report.events_claimed > 0 => {
                        info!(
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
                    Err(err) => {
                        // The next tick retries; claim leases make a crash
                        // mid-tick a recoverable state.
                        error!(error = %err, "automation executor tick failed");
                    }
                }
            }
        }));
    }

    info!("All processors running. Press Ctrl+C to stop.");

    Ok(WorkerProcesses {
        handles,
        analytics: analytics_processor,
        email: email_processor,
        reply: reply_processor,
        webhook: webhook_processor,
        automations: automations_task,
        heartbeat,
    })
}

/// Serve /health and /metrics on an INJECTED listener. Runs until the task
/// is aborted; extraction keeps the bind out of the tested body.
async fn run_health_server(
    listener: tokio::net::TcpListener,
    metrics_handler: metrics_exporter_prometheus::PrometheusHandle,
) {
    let metrics_handler = std::sync::Arc::new(metrics_handler);
    let health_app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/metrics",
            get(move || {
                let metrics_handle = metrics_handler.clone();
                async move {
                    (
                        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
                        metrics_handle.render(),
                    )
                        .into_response()
                }
            }),
        );
    if let Err(e) = axum::serve(listener, health_app).await {
        error!(error = %e, "Health check server failed");
    }
}

/// Resolve the health port: HEALTH_PORT wins, then METRICS_PORT (the compose
/// file configures 9093), then 9090.
fn health_port() -> u16 {
    env::var("HEALTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| env::var("METRICS_PORT").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(9090)
}

/// Stop every processor, then join their tasks with a bounded wait. A
/// shutdown that exceeds `timeout` logs and returns (the process exits).
async fn shutdown_worker(processes: WorkerProcesses, shutdown_timeout: Duration) {
    // The automation tick has no stop() handshake: abort it (safe — leased
    // claims and exactly-once identities make an interrupted tick recoverable)
    // before joining the supervised processors.
    if let Some(handle) = &processes.automations {
        handle.abort();
    }
    if let Some(processor) = &processes.analytics {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop analytics processor");
        }
    }
    if let Some(processor) = &processes.email {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop email processor");
        }
    }
    if let Some(processor) = &processes.reply {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop reply handler");
        }
    }
    if let Some(processor) = &processes.webhook {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop webhook processor");
        }
    }

    let join_all = async {
        for handle in processes.handles {
            if let Err(error) = handle.await {
                warn!(error = %error, "Processor task join failed during shutdown");
            }
        }
    };

    if tokio::time::timeout(shutdown_timeout, join_all)
        .await
        .is_err()
    {
        warn!("Shutdown timed out; some processor tasks may still be running");
    }

    // Stop beating; the control plane sees the lease go stale on its own.
    processes.heartbeat.abort();
}

/// A worker identity that is unique per process across replicas.
///
/// The PID alone is not a valid replica identity — separate containers
/// routinely share the same PID number — so the hostname and a random suffix
/// are included. The automation executor's lease token is what actually
/// fences writes; this string only makes the owner column diagnosable.
fn unique_worker_id() -> String {
    let host = env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".into());
    format!("{}:{}:{}", host, std::process::id(), uuid::Uuid::new_v4())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring CryptoProvider for rustls before any TLS-capable code
    // runs. The workspace enables both `ring` (workspace rustls) and
    // aws-lc-rs (via reqwest's `rustls-tls`, sqlx, mail-send), so rustls
    // cannot pick a default provider on its own and would panic on the first
    // TLS handshake (email SMTP TLS verify, webhook HTTPS delivery, SES).
    // Installing explicitly keeps the provider deterministic across builds.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let _guard = init_tracing();

    // Keep health and Prometheus metrics on the worker's probe port. The
    // service previously accepted TCP connections there but returned no
    // scrapeable metrics, which made the configured monitoring target fail.
    let metrics_recorder = PrometheusBuilder::new().build_recorder();
    let metrics_handle = metrics_recorder.handle();
    if let Err(error) = metrics::set_global_recorder(Box::new(metrics_recorder)) {
        warn!(error = %error, "Prometheus recorder already installed");
    }
    metrics::gauge!("apexmail_worker_info").set(1.0);

    info!("Starting ApexMail Worker (Rust)");

    // Load configuration from environment
    let database_url = env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable must be set"))?;
    let redis_url = env::var("REDIS_URL")
        .map_err(|_| anyhow::anyhow!("REDIS_URL environment variable must be set"))?;

    let db = connect_db(&database_url).await?;
    info!("Connected to PostgreSQL");

    let redis = connect_redis(&redis_url)?;
    info!("Connected to Redis");

    let settings = load_worker_settings();
    let processes = run_worker(db, redis, &settings).await?;

    // Start health check server for Kubernetes probes. Honors HEALTH_PORT and
    // falls back to METRICS_PORT so the container healthcheck and the
    // listener always agree.
    let health_addr = SocketAddr::from(([0, 0, 0, 0], health_port()));
    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    info!(port = health_port(), "Health check server listening");
    tokio::spawn(run_health_server(health_listener, metrics_handle));

    // Wait for shutdown signal (SIGINT or SIGTERM)
    {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
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
            _ = ctrl_c => info!("received Ctrl+C"),
            _ = terminate => info!("received SIGTERM"),
        }
    }

    info!("Shutting down...");
    shutdown_worker(processes, Duration::from_secs(10)).await;
    info!("Worker stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The supervisor is the only piece of the worker binary that can be
    //! exercised without a live broker: a clean shutdown must end supervision,
    //! and a failing processor must be restarted under a capped backoff.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Single crate-wide lock serializing env-mutating tests (each nextest
    /// test is its own process, but `cargo test` runs them on shared threads).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Same deterministic AWS environment the lib's test fixtures install
    /// (metadata probing off, file-based rustls roots) — `run_worker` builds
    /// the SES transport via `EmailProcessor::new`.
    fn ensure_aws_test_env() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
            for var in ["SSL_CERT_FILE", "AWS_CA_BUNDLE"] {
                if std::env::var_os(var).is_none() {
                    for candidate in [
                        "/etc/ssl/cert.pem",
                        "/etc/ssl/certs/ca-certificates.crt",
                        "/etc/pki/tls/certs/ca-bundle.crt",
                    ] {
                        if std::path::Path::new(candidate).is_file() {
                            std::env::set_var(var, candidate);
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Run `body` with the listed env vars forced to values, restoring the
    /// previous state afterwards (unset stays unset).
    fn with_env(vars: &[(&str, Option<&str>)], body: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let saved: Vec<(&str, Option<std::ffi::OsString>)> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var_os(k)))
            .collect();
        for (k, v) in vars {
            match v {
                Some(value) => std::env::set_var(k, value),
                None => std::env::remove_var(k),
            }
        }
        body();
        for (k, v) in saved {
            match v {
                Some(previous) => std::env::set_var(k, previous),
                None => std::env::remove_var(k),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn supervise_returns_on_a_clean_shutdown_without_restarting() {
        let calls = AtomicUsize::new(0);
        let liveness = ProcessorLiveness::new();
        supervise("clean", liveness.clone(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "Ok(()) ends supervision");
        assert!(
            !liveness.is_alive("clean"),
            "a cleanly shut down processor must not stay registered alive"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn supervise_restarts_a_failed_processor_with_backoff() {
        let calls = AtomicUsize::new(0);
        let liveness = ProcessorLiveness::new();
        supervise("flaky", liveness.clone(), || {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err(worker_processors::ProcessorError::Job(format!(
                        "transient failure {attempt}"
                    )))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "each failure must restart the processor until it shuts down cleanly"
        );
    }

    /// SM10 F1: a processor that PANICS must not kill supervision. The panic
    /// unwinds through the spawned attempt task; the supervisor observes it
    /// on the `JoinHandle`, emits the processor-dead metric, clears the
    /// heartbeat liveness entry for the backoff window, and restarts per the
    /// existing policy. The replacement attempt shuts down cleanly so the
    /// test terminates.
    #[tokio::test(start_paused = true)]
    async fn supervise_catches_a_panicking_processor_and_restarts_it() {
        // Silence the default hook for the deliberate test panic.
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let calls = Arc::new(AtomicUsize::new(0));
        let attempt_counter = Arc::clone(&calls);
        let liveness = ProcessorLiveness::new();
        let supervisor = tokio::spawn(supervise("panicky", liveness.clone(), move || {
            let attempt = attempt_counter.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    panic!("boom: processor exploded");
                }
                // The replacement attempt STAYS ALIVE until the test
                // ends it — this is the window in which the heartbeat
                // must advertise the processor again. (A clean `Ok(())`
                // would legitimately clear the registration on return.)
                std::future::pending::<worker_processors::ProcessorResult<()>>().await
            }
        }));
        // Two attempts: the first panics, the supervisor sleeps out the
        // backoff (auto-advanced on the paused clock) and respawns.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while calls.load(Ordering::SeqCst) < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the supervisor never restarted the panicked processor"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            liveness.is_alive("panicky"),
            "the replacement attempt must be registered alive while it runs"
        );
        supervisor.abort();
        std::panic::set_hook(default_hook);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the panic must be caught and the processor restarted exactly once"
        );
    }

    /// The registry the heartbeat reads: the alive transition registers a
    /// running attempt, the dead transition clears it (a dead processor's
    /// capability entry must vanish from the next beat).
    #[test]
    fn processor_liveness_registry_tracks_running_attempts() {
        let liveness = ProcessorLiveness::new();
        assert!(!liveness.is_alive("email"), "nothing registered yet");
        liveness.set_alive("email", true);
        assert!(liveness.is_alive("email"));
        liveness.set_alive("email", false);
        assert!(
            !liveness.is_alive("email"),
            "the dead transition must clear the registry entry"
        );
    }

    #[test]
    fn worker_settings_parse_every_env_arm() {
        with_env(
            &[
                ("WORKER_CONCURRENCY", Some("0")),
                ("WORKER_POLL_INTERVAL", Some("not-a-number")),
                ("WORKER_RUN_ANALYTICS", Some("false")),
                ("WORKER_RUN_EMAIL", Some("0")),
                ("WORKER_RUN_REPLY_HANDLER", Some("1")),
                ("WORKER_RUN_WEBHOOK", Some("true")),
                ("WORKER_RUN_AUTOMATIONS", Some("false")),
                ("AUTOMATION_TICK_SECS", Some("7")),
            ],
            || {
                let s = load_worker_settings();
                assert_eq!(s.concurrency, 1, "a zero concurrency is clamped up to 1");
                assert_eq!(
                    s.poll_interval,
                    Duration::from_secs(5),
                    "invalid interval falls back to 5s"
                );
                assert!(!s.run_analytics, "false disables");
                assert!(!s.run_email, "0 disables");
                assert!(s.run_reply_handler, "1 enables");
                assert!(s.run_webhook, "true enables");
                assert!(!s.run_automations, "false disables the automation tick");
                assert_eq!(
                    automation_tick_secs(),
                    7,
                    "AUTOMATION_TICK_SECS overrides the default period"
                );
            },
        );
        with_env(
            &[
                ("WORKER_CONCURRENCY", Some("32")),
                ("WORKER_POLL_INTERVAL", Some("2")),
                ("WORKER_RUN_ANALYTICS", Some("garbage")),
                ("AUTOMATION_TICK_SECS", Some("0")),
            ],
            || {
                let s = load_worker_settings();
                assert_eq!(s.concurrency, 32);
                assert_eq!(s.poll_interval, Duration::from_secs(2));
                // Any explicit value other than true/1 DISABLES the processor.
                assert!(!s.run_analytics, "unknown flag value disables");
                assert!(
                    s.run_email && s.run_reply_handler && s.run_webhook && s.run_automations,
                    "every processor defaults to enabled"
                );
                assert_eq!(
                    automation_tick_secs(),
                    1,
                    "a zero/negative tick period is clamped to one second"
                );
            },
        );
        // Sequential, NOT nested: with_env holds ENV_LOCK for its body, so a
        // nested with_env re-locks the same std Mutex on the same thread and
        // deadlocks deterministically (the hang was visible as a 3600 s
        // nextest timeout).
        with_env(&[("AUTOMATION_TICK_SECS", None)], || {
            assert_eq!(
                automation_tick_secs(),
                AUTOMATION_TICK_SECS_DEFAULT,
                "unset cadence falls back to the default"
            );
        });
        with_env(&[("AUTOMATION_TICK_SECS", Some(" 45 "))], || {
            assert_eq!(
                automation_tick_secs(),
                45,
                "whitespace around the value is tolerated"
            );
        });
        with_env(&[("AUTOMATION_TICK_SECS", Some("soon"))], || {
            assert_eq!(
                automation_tick_secs(),
                AUTOMATION_TICK_SECS_DEFAULT,
                "an invalid cadence falls back to the default"
            );
        });
    }

    #[test]
    fn capabilities_reflect_enabled_processors() {
        let base = WorkerSettings {
            concurrency: 4,
            poll_interval: Duration::from_secs(1),
            run_analytics: false,
            run_email: false,
            run_reply_handler: false,
            run_webhook: false,
            run_automations: false,
        };
        let liveness = ProcessorLiveness::new();
        assert_eq!(
            heartbeat_capabilities(&base, &liveness),
            ["postgres", "redis"]
        );
        let all = WorkerSettings {
            run_analytics: true,
            run_email: true,
            run_reply_handler: true,
            run_webhook: true,
            run_automations: true,
            ..base
        };
        // Nothing registered alive yet: enabled-but-dead processors must NOT
        // be advertised (SM10 F1 — the heartbeat previously advertised every
        // enabled processor unconditionally, even one that had panicked).
        assert_eq!(
            heartbeat_capabilities(&all, &liveness),
            ["postgres", "redis", "automations"]
        );
        // Once supervision registers the attempts alive, the capabilities
        // reappear.
        liveness.set_alive("analytics", true);
        liveness.set_alive("email", true);
        liveness.set_alive("reply-handler", true);
        liveness.set_alive("webhook", true);
        assert_eq!(
            heartbeat_capabilities(&all, &liveness),
            [
                "postgres",
                "redis",
                "analytics",
                "email",
                "reply-handler",
                "webhook",
                "automations"
            ]
        );
        // A processor dying between beats loses ONLY its own entry.
        liveness.set_alive("email", false);
        assert_eq!(
            heartbeat_capabilities(&all, &liveness),
            [
                "postgres",
                "redis",
                "analytics",
                "reply-handler",
                "webhook",
                "automations"
            ]
        );
        // And a disabled processor is never advertised even if a stale entry
        // lingered.
        let stale_liveness = ProcessorLiveness::new();
        stale_liveness.set_alive("webhook", true);
        assert!(
            !heartbeat_capabilities(&base, &stale_liveness).contains(&"webhook".to_string()),
            "disabled processors stay out of the heartbeat regardless of liveness"
        );
    }

    #[test]
    fn unique_worker_id_is_host_pid_and_random() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOSTNAME", "worker-host-9");
        let id = unique_worker_id();
        assert!(id.starts_with("worker-host-9:"), "{id}");
        let parts: Vec<&str> = id.split(':').collect();
        assert_eq!(parts.len(), 3, "host:pid:uuid — {id}");
        assert!(parts[1].parse::<u32>().is_ok(), "pid component — {id}");
        assert!(
            uuid::Uuid::parse_str(parts[2]).is_ok(),
            "random uuid component — {id}"
        );
        assert_ne!(id, unique_worker_id(), "ids are unique per call");
        std::env::remove_var("HOSTNAME");
    }

    #[test]
    fn verp_gate_refuses_production_email_without_the_shared_secret() {
        // Production + email + missing secret: hard error.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", None),
                ("VERP_DOMAIN", None),
            ],
            || {
                let err = verp_secret_gate(true).expect_err("production must refuse");
                assert!(
                    format!("{err:#}").contains("VERP_HMAC_SECRET must be set"),
                    "{err:#}"
                );
            },
        );
        // "prod" is accepted as production too (with an empty VERP_DOMAIN
        // explicitly given).
        with_env(
            &[
                ("NODE_ENV", Some(" prod ")),
                ("VERP_HMAC_SECRET", Some("short")),
                ("VERP_DOMAIN", Some("bounces.example.test")),
            ],
            || {
                assert!(
                    verp_secret_gate(true).is_err(),
                    "a too-short secret still refuses"
                );
            },
        );
        // Production but the email processor is off: warn-only.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", None),
                ("VERP_DOMAIN", None),
            ],
            || {
                assert!(
                    verp_secret_gate(false).is_ok(),
                    "no email processor => warn only"
                );
            },
        );
        // VERP explicitly disabled by an empty domain: never fatal.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", None),
                ("VERP_DOMAIN", Some("   ")),
            ],
            || {
                assert!(
                    verp_secret_gate(true).is_ok(),
                    "disabled VERP domain => warn only"
                );
            },
        );
        // A long-enough secret in production passes cleanly.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", Some("0123456789abcdef0123456789abcdef")),
                ("VERP_DOMAIN", None),
            ],
            || {
                assert!(verp_secret_gate(true).is_ok(), "valid secret passes");
            },
        );
        // Development without a secret: warn-only.
        with_env(
            &[
                ("NODE_ENV", Some("development")),
                ("VERP_HMAC_SECRET", None),
            ],
            || {
                assert!(
                    verp_secret_gate(true).is_ok(),
                    "development degrades to a warning"
                );
            },
        );
    }

    #[test]
    fn smtp_host_resolution_arms() {
        use worker_processors::common::SmtpConfig;
        // SMTP transport without a host: hard error.
        with_env(&[("SMTP_HOST", None)], || {
            let err = smtp_host_for(&TransportType::Smtp).expect_err("smtp needs SMTP_HOST");
            assert!(
                format!("{err:#}").contains("SMTP_HOST environment variable must be set"),
                "{err:#}"
            );
        });
        // Empty SMTP_HOST is treated as missing for smtp, and as "not
        // configured" for ses (sentinel host).
        with_env(&[("SMTP_HOST", Some(""))], || {
            assert!(smtp_host_for(&TransportType::Smtp).is_err());
            let host = smtp_host_for(&TransportType::Ses).expect("ses tolerates no relay");
            assert_eq!(
                host,
                SmtpConfig::default().host,
                "ses keeps the sentinel host"
            );
        });
        // An explicit host wins for both transports.
        with_env(&[("SMTP_HOST", Some("relay.example.test"))], || {
            assert_eq!(
                smtp_host_for(&TransportType::Smtp).unwrap(),
                "relay.example.test"
            );
            assert_eq!(
                smtp_host_for(&TransportType::Ses).unwrap(),
                "relay.example.test"
            );
        });
    }

    #[test]
    fn email_config_assembles_env_settings() {
        ensure_aws_test_env();
        with_env(
            &[
                ("EMAIL_TRANSPORT_TYPE", Some("smtp")),
                ("SMTP_HOST", Some("relay.example.test")),
                ("SMTP_PORT", Some("2525")),
                ("SMTP_TLS", Some("false")),
                ("SMTP_USERNAME", Some("user")),
                ("SMTP_PASSWORD", Some("pass")),
                ("AWS_REGION", Some("eu-west-1")),
                ("SES_CONFIGURATION_SET", Some("cs-1")),
                ("DKIM_ENABLED", Some("1")),
                ("TRACKING_ENABLED", Some("true")),
                (
                    "TRACKING_SECRET_KEY",
                    Some("0123456789abcdef0123456789abcdef"),
                ),
            ],
            || {
                let cfg = build_email_config(7, Duration::from_secs(3)).expect("config builds");
                assert_eq!(cfg.transport_type, TransportType::Smtp);
                assert_eq!(cfg.smtp.host, "relay.example.test");
                assert_eq!(cfg.smtp.port, 2525);
                assert!(!cfg.smtp.secure);
                assert_eq!(cfg.smtp.username.as_deref(), Some("user"));
                assert_eq!(
                    cfg.smtp.password.as_ref().map(|p| p.as_str().to_string()),
                    Some("pass".to_string())
                );
                assert_eq!(cfg.ses.region, "eu-west-1");
                assert_eq!(cfg.ses.configuration_set.as_deref(), Some("cs-1"));
                assert!(cfg.dkim.enabled);
                assert!(
                    cfg.tracking.enabled,
                    "tracking must follow TRACKING_ENABLED"
                );
                assert_eq!(cfg.base.concurrency, 7);
                assert_eq!(cfg.base.poll_interval, Duration::from_secs(3));
            },
        );
        // SES default transport: no SMTP_HOST needed.
        with_env(
            &[
                ("EMAIL_TRANSPORT_TYPE", None),
                ("SMTP_HOST", None),
                ("SMTP_PORT", Some("nope")),
                ("DKIM_ENABLED", None),
                ("AWS_REGION", Some("  ")),
            ],
            || {
                let cfg = build_email_config(1, Duration::from_secs(1)).expect("ses config builds");
                assert_eq!(cfg.transport_type, TransportType::Ses);
                assert_eq!(cfg.smtp.port, 587, "invalid SMTP_PORT falls back to 587");
                assert!(!cfg.dkim.enabled);
                assert_eq!(cfg.ses.region, "us-east-1", "blank AWS_REGION falls back");
            },
        );
    }

    #[test]
    fn health_port_prefers_health_then_metrics_then_default() {
        with_env(&[("HEALTH_PORT", None), ("METRICS_PORT", None)], || {
            assert_eq!(health_port(), 9090);
        });
        with_env(
            &[("HEALTH_PORT", None), ("METRICS_PORT", Some("9093"))],
            || {
                assert_eq!(health_port(), 9093);
            },
        );
        with_env(
            &[
                ("HEALTH_PORT", Some("18080")),
                ("METRICS_PORT", Some("9093")),
            ],
            || {
                assert_eq!(health_port(), 18080, "HEALTH_PORT wins");
            },
        );
        with_env(
            &[("HEALTH_PORT", Some("bad")), ("METRICS_PORT", None)],
            || {
                assert_eq!(health_port(), 9090, "invalid HEALTH_PORT falls through");
            },
        );
    }

    #[tokio::test]
    async fn connect_db_rejects_a_malformed_url_immediately() {
        let err = connect_db("totally not a url")
            .await
            .expect_err("parse failure");
        assert!(
            format!("{err:#}").to_lowercase().contains("url"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn connect_redis_rejects_a_malformed_url() {
        assert!(
            connect_redis("not a redis url at all").is_err(),
            "deadpool must refuse an unparseable URL"
        );
    }

    /// The real health server on a loopback ephemeral port: /health answers
    /// OK and /metrics renders scrapeable Prometheus text.
    #[tokio::test]
    async fn health_server_serves_health_and_prometheus_metrics() {
        // Build a recorder without installing it globally (tests share a process).
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // Record one counter through the LOCAL recorder (the global one is not
        // installed in the test process) so the render is non-empty.
        {
            // Scope a real macro-driven counter through the LOCAL recorder so
            // the rendered output is non-empty.
            metrics::with_local_recorder(&recorder, || {
                metrics::counter!("apexmail_worker_test_up").increment(1);
            });
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral health port");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(run_health_server(listener, handle));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("client");
        let health = client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .expect("GET /health");
        assert_eq!(health.status(), 200);
        assert_eq!(health.text().await.expect("body"), "OK");

        let metrics = client
            .get(format!("http://127.0.0.1:{port}/metrics"))
            .send()
            .await
            .expect("GET /metrics");
        assert_eq!(metrics.status(), 200);
        let headers = metrics.headers().clone();
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.starts_with("text/plain"), "{content_type}");
        let body = metrics.text().await.expect("metrics body");
        assert!(body.contains("apexmail_worker_test_up"), "{body}");

        server.abort();
    }

    /// `run_worker` against a fresh canonical DB + real Redis starts every
    /// enabled processor; `shutdown_worker` stops and joins them.
    #[tokio::test]
    async fn run_worker_starts_all_processors_and_shutdown_joins_them() {
        ensure_aws_test_env();
        let db = match migrator::test_support::fresh_canonical_pool(
            "worker_bin_run_worker",
            "bin_run_worker",
        )
        .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => {
                eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
                return;
            }
            Err(e) => panic!("provision failed: {e}"),
        };
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = connect_redis(&redis_url).expect("test redis pool");

        let settings = WorkerSettings {
            concurrency: 2,
            poll_interval: Duration::from_secs(60),
            run_analytics: true,
            run_email: true,
            run_reply_handler: true,
            run_webhook: true,
            run_automations: true,
        };
        let processes = run_worker(db.clone(), redis.clone(), &settings)
            .await
            .expect("all processors start");
        assert!(processes.analytics.is_some(), "analytics started");
        assert!(processes.email.is_some(), "email started");
        assert!(processes.reply.is_some(), "reply handler started");
        assert!(processes.webhook.is_some(), "webhook started");
        assert!(
            processes.automations.is_some(),
            "the customer automation executor started"
        );
        assert_eq!(processes.handles.len(), 4, "one supervised task each");

        shutdown_worker(processes, Duration::from_secs(10)).await;
        db.close().await;
    }

    /// A disabled processor is neither built nor supervised; the VERP gate
    /// failure aborts startup with an error.
    #[tokio::test]
    async fn run_worker_selective_flags_and_verp_refusal() {
        ensure_aws_test_env();
        let db = match migrator::test_support::fresh_canonical_pool(
            "worker_bin_verp_gate",
            "bin_verp_gate",
        )
        .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => {
                eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
                return;
            }
            Err(e) => panic!("provision failed: {e}"),
        };
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = connect_redis(&redis_url).expect("test redis pool");

        let settings = WorkerSettings {
            concurrency: 1,
            poll_interval: Duration::from_secs(60),
            run_analytics: false,
            run_email: false,
            run_reply_handler: true,
            run_webhook: false,
            run_automations: false,
        };
        let processes = run_worker(db.clone(), redis.clone(), &settings)
            .await
            .expect("only the reply handler runs");
        assert!(processes.analytics.is_none());
        assert!(processes.email.is_none());
        assert!(processes.reply.is_some());
        assert!(processes.webhook.is_none());
        assert!(
            processes.automations.is_none(),
            "the automation tick honours its disable flag"
        );
        assert_eq!(processes.handles.len(), 1);
        shutdown_worker(processes, Duration::from_secs(10)).await;

        // Production VERP refusal: email enabled without the secret aborts
        // run_worker AFTER the heartbeat started (matching production's
        // ordering) and before the email processor is created.
        let saved = (
            std::env::var_os("NODE_ENV"),
            std::env::var_os("VERP_HMAC_SECRET"),
        );
        {
            let _guard = ENV_LOCK.lock().expect("env lock");
            std::env::set_var("NODE_ENV", "production");
            std::env::remove_var("VERP_HMAC_SECRET");
        }
        let settings = WorkerSettings {
            run_analytics: false,
            run_email: true,
            run_reply_handler: false,
            run_webhook: false,
            ..settings
        };
        let result = run_worker(db.clone(), redis.clone(), &settings).await;
        match saved {
            (Some(env), _) => std::env::set_var("NODE_ENV", env),
            (None, _) => std::env::remove_var("NODE_ENV"),
        }
        match saved.1 {
            Some(secret) => std::env::set_var("VERP_HMAC_SECRET", secret),
            None => std::env::remove_var("VERP_HMAC_SECRET"),
        }
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("production VERP gate must refuse, but run_worker succeeded"),
        };
        assert!(
            format!("{err:#}").contains("VERP_HMAC_SECRET must be set"),
            "{err:#}"
        );
        db.close().await;
    }

    /// The production connect path builds a WORKING pool: the exact
    /// `PgConnectOptions` tunings (statement cache, acquire/idle/lifetime
    /// limits) must still serve queries against the configured database.
    #[tokio::test]
    async fn connect_db_serves_queries_with_production_tunings() -> Result<()> {
        let Some(url) = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
        else {
            return Ok(());
        };
        let pool = connect_db(&url).await.expect("the test server connects");
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("the pool must serve a query with statement caching enabled");
        assert_eq!(one, 1);
        pool.close().await;
        Ok(())
    }

    /// With OTLP disabled, `init_tracing` installs the structured-JSON
    /// fallback subscriber and reports no guard. (Single-shot: the global
    /// subscriber slot is taken by the first install, so this test must be
    /// the only caller in the binary's test binary.)
    #[test]
    fn init_tracing_falls_back_to_json_logging_without_otlp() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let saved = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        let guard = std::panic::catch_unwind(init_tracing);
        match saved {
            Some(v) => std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", v),
            None => std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT"),
        }
        // `None` = the fallback path ran (no OTLP guard to flush). A panic
        // here would mean a global subscriber was already installed — an
        // environment fault, surfaced loudly instead of silently skipped.
        let guard = guard.expect("the fallback install must not panic");
        assert!(
            guard.is_none(),
            "without OTLP there is no tracing guard to keep alive"
        );
    }
}
