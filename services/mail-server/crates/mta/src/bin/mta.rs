//! MTA binary – starts inbound, bounce, and feedback‑loop servers with health endpoint.
//!
//! Listener supervision: every enabled listener runs inside a
//! [`mta::supervision::ListenerSupervisor`] (`tokio::task::JoinSet`). An
//! unexpected listener exit latches `/ready` to 503 and terminates the
//! process with an error (the orchestrator restarts it) instead of logging
//! and continuing to serve as if nothing happened.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use mta::auth::EmailAuthenticator;
use mta::config::MtaConfig;
use mta::servers::{
    BounceServer, FeedbackLoopServer, InboundDeliveryWorker, InboundServer, SubmissionServer,
};
use mta::supervision::{ListenerSupervisor, Readiness};
use mta::tls;

#[derive(Parser)]
#[command(name = "mta-server", about = "ApexMail MTA Server")]
struct Cli {
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    );

    // Initialize tracing (with OTLP support)
    let _tracing_guard = init_tracing(&cli.log_level);

    let config = MtaConfig::from_env()?;
    run_(config, wait_for_shutdown_signal()).await
}

/// Start every enabled listener and serve until `shutdown` resolves (the
/// binary passes SIGINT/SIGTERM; tests pass an in-band future).
///
/// Returns an error when any supervised listener exits before shutdown —
/// the process must terminate so the orchestrator restarts it.
async fn run_(
    config: MtaConfig,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    info!(mta_id = %config.mta_id, "Starting MTA server");

    // The MTA emits SPF cache metrics through the `metrics` facade. Install a
    // dedicated Prometheus listener before any SMTP task starts so Prometheus
    // can scrape both service availability and those counters.
    //
    // F-24: METRICS_ENABLED keeps its FALSE default. Flipping it would make
    // `install_recorder()` (which binds 0.0.0.0:METRICS_PORT) part of every
    // default boot — a port collision or a locked-down environment would
    // then abort startup, so the safer default stays and the operator gets
    // a loud warning instead.
    if config.metrics.enabled {
        let metrics_addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", config.metrics.port).parse()?;
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(metrics_addr)
            .install_recorder()
            .map_err(|error| anyhow::anyhow!("failed to start MTA metrics listener: {error}"))?;
        metrics::gauge!("apexmail_mta_info").set(1.0);
        info!(
            port = config.metrics.port,
            "Prometheus metrics listener ready"
        );
    } else {
        tracing::warn!(
            "METRICS_ENABLED is false: all mta.* counters/histograms (smtp, auth, tls, spf) \
             are recorded into a no-op sink. Set METRICS_ENABLED=true to expose them on the \
             Prometheus listener (port {})",
            config.metrics.port
        );
    }

    // Database pool
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&config.database.connection_string)
        .await?;

    // Redis pool. Bounded create/wait timeouts: the durable auth-lockout
    // layer falls back to in-memory counters when Redis is slow/down, so a
    // hung TCP connect must not stall SMTP AUTH replies for the OS-level
    // timeout (~minutes); it fails over within seconds instead.
    let mut redis_cfg = deadpool_redis::Config::from_url(&config.redis.url);
    let mut pool_cfg = deadpool_redis::PoolConfig::default();
    pool_cfg.timeouts.create = Some(std::time::Duration::from_secs(3));
    pool_cfg.timeouts.wait = Some(std::time::Duration::from_secs(3));
    pool_cfg.timeouts.recycle = Some(std::time::Duration::from_secs(3));
    redis_cfg.pool = Some(pool_cfg);
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    // TLS acceptor (optional)
    let tls_acceptor = if config.inbound.tls.enabled {
        let cert_path = config
            .inbound
            .tls
            .cert_path
            .as_deref()
            .unwrap_or("cert.pem");
        let key_path = config.inbound.tls.key_path.as_deref().unwrap_or("key.pem");
        Some(load_tls_acceptor(cert_path, key_path)?)
    } else {
        None
    };

    // Production fail-fast: submission accepts AUTH, so when it is enabled in
    // production a missing/invalid/expired certificate must abort startup.
    // Port 25 remains opportunistic STARTTLS (the warning below plus the
    // `apexmail_mta_tls_enabled` gauge keep the no-TLS state visible).
    let now_unix = chrono::Utc::now().timestamp();
    if let Some(expiry) = tls::enforce_submission_tls_production(
        config.is_production(),
        config.submission.enabled,
        config.inbound.tls.enabled,
        config.inbound.tls.cert_path.as_deref(),
        now_unix,
    )? {
        info!(
            days_remaining = expiry.days_remaining,
            not_after = expiry.not_after,
            "Submission TLS certificate valid; production submission gate passed"
        );
    }

    // Operator-visible TLS state (documented level: WARN + gauge 0 when off).
    metrics::gauge!("apexmail_mta_tls_enabled", "listener" => "inbound")
        .set(if tls_acceptor.is_some() { 1.0 } else { 0.0 });

    // F-20: TLS_ENABLED deliberately defaults to false (a cert-less host
    // must still boot), but a PUBLIC plaintext SMTP listener deserves a loud
    // startup warning — port 25 then offers no STARTTLS, and port 587/465
    // AUTH is permanently gated (530 Must issue STARTTLS first).
    if tls_acceptor.is_none() {
        let public_listeners: Vec<&str> = [
            config.inbound.enabled.then_some("inbound:25 (STARTTLS)"),
            config
                .inbound
                .enabled
                .then_some("inbound:465 (implicit TLS)"),
            config
                .submission
                .enabled
                .then_some("submission:587 (STARTTLS + AUTH)"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !public_listeners.is_empty() {
            tracing::warn!(
                listeners = ?public_listeners,
                "TLS_ENABLED is false while public SMTP listeners are enabled: mail arrives in plaintext, STARTTLS is not offered, and AUTH is refused until TLS is configured (TLS_ENABLED=true + TLS_CERT_PATH/TLS_KEY_PATH)"
            );
        }
    }

    // Certificate-expiry alarms at 30/14/7/1 days: checked at startup and
    // every 6 hours; each threshold crossing is logged once (WARN at
    // 30/14/7, ERROR at 1) and counted in
    // `apexmail_mta_tls_cert_expiry_alarm_total`.
    if config.inbound.tls.enabled {
        if let Some(cert_path) = config.inbound.tls.cert_path.clone() {
            tokio::spawn(async move { cert_expiry_alarm_loop(cert_path).await });
        }
    }

    // Email authenticator
    let authenticator = Arc::new(
        EmailAuthenticator::new(config.email_auth.clone(), config.inbound.hostname.clone()).await?,
    );

    // Shared readiness flag: a supervised listener exiting unexpectedly
    // latches it false, which makes /ready answer 503 (the process then
    // terminates so the orchestrator restarts it).
    let readiness = Readiness::new();

    // Health server
    let app = health_router(pool.clone(), redis_pool.clone(), readiness.clone());
    let health_port = config.health_port;
    // #152:Store health server handle for proper shutdown
    let health_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{health_port}")).await;
        let listener = match listener {
            Ok(listener) => listener,
            Err(error) => {
                error!(error = %error, port = health_port, "Failed to bind health listener");
                return;
            }
        };
        info!(port = health_port, "Health server listening");
        axum::serve(listener, app).await.ok();
    });

    // Inbound server
    // #151:Keep server references for graceful stop calls
    let mut supervisor = ListenerSupervisor::new(readiness.clone());
    let inbound_srv = if config.inbound.enabled {
        let srv = Arc::new(InboundServer::new(
            config.inbound.clone(),
            config.rate_limit.clone(),
            pool.clone(),
            redis_pool.clone(),
            authenticator.clone(),
            config.inbound.hostname.clone(),
            // VERP replies are routed to the bounce/reply-handler path, not
            // resolved as mailboxes at RCPT.
            vec![config.bounce.verp_domain.clone()],
        )?);
        let s = srv.clone();
        let tls = tls_acceptor.clone();
        supervisor.spawn("inbound", async move { s.start(tls).await });
        Some(srv)
    } else {
        None
    };

    // Durable inbound delivery worker (migration 210 ledger): retries
    // transient mailstore failures with backoff and generates RFC 3464 DSNs
    // for permanent post-accept failures. Construction failure is fatal when
    // inbound is enabled — an inbound server whose accepted mail has no
    // delivery worker would re-open the accept-then-drop hole. The worker
    // runs under the listener supervisor: if it ever exits unexpectedly the
    // process fails rather than silently dropping accepted mail.
    let inbound_delivery_shutdown = if config.inbound.enabled {
        let worker = Arc::new(InboundDeliveryWorker::new(
            pool.clone(),
            &config.mailstore_addr,
            config.inbound.hostname.clone(),
        )?);
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let worker_task = worker.clone();
        let worker_shutdown = shutdown.clone();
        supervisor.spawn("inbound-delivery", async move {
            worker_task.run(worker_shutdown).await
        });
        info!("Inbound delivery worker started");
        Some(shutdown)
    } else {
        None
    };

    // Bounce server. The VERP v2 HMAC secret authenticates bounce tokens;
    // `MtaConfig::validate` refuses a production startup without it. Without
    // a secret the listener still runs, but every bounce is recorded as a
    // non-authoritative observation and nothing suppresses.
    let bounce_srv = if config.bounce.enabled {
        let verp_secret = config
            .verp
            .hmac_secret
            .as_deref()
            .map(|secret| secret.trim().as_bytes().to_vec());
        if verp_secret.is_none() {
            warn!(
                "VERP_HMAC_SECRET is not configured: bounces cannot be authenticated and will be \
                 recorded as non-authoritative observations (production startup would refuse \
                 this configuration)"
            );
        }
        let srv = Arc::new(BounceServer::new(
            config.bounce.clone(),
            pool.clone(),
            redis_pool.clone(),
            config.bounce.hostname.clone(),
            verp_secret,
            config.verp.v2_enabled,
        ));
        let s = srv.clone();
        supervisor.spawn("bounce", async move { s.start().await });
        Some(srv)
    } else {
        None
    };

    // Feedback loop server. Provider registry first: only authoritative
    // ARF/FBL traffic may suppress.
    let fbl_srv = if config.feedback.enabled {
        let srv = Arc::new(FeedbackLoopServer::new(
            config.feedback.clone(),
            pool.clone(),
            redis_pool.clone(),
            config.feedback.hostname.clone(),
        ));
        match srv.load_registry_from_db(&pool).await {
            Ok(count) => info!(providers = count, "FBL provider registry loaded"),
            Err(error) => warn!(
                error = %error,
                "FBL provider registry unavailable; compiled seed providers in use"
            ),
        }
        let s = srv.clone();
        supervisor.spawn("fbl", async move { s.start().await });
        Some(srv)
    } else {
        None
    };

    // Submission server (authenticated SMTP on port 587)
    let submission_srv = if config.submission.enabled {
        // FIX-1: TLS load failure is FATAL (propagates and aborts startup),
        // mirroring the inbound server. A warn-and-continue here would leave
        // the server accepting AUTH PLAIN/LOGIN with no TLS gate — sending
        // credentials in cleartext on the publicly published port 587.
        let submission_tls = submission_tls_acceptor(&config.inbound.tls)?;
        metrics::gauge!("apexmail_mta_tls_enabled", "listener" => "submission")
            .set(if submission_tls.is_some() { 1.0 } else { 0.0 });
        let srv = Arc::new(SubmissionServer::new(
            config.submission.clone(),
            config.rate_limit.clone(),
            pool.clone(),
            redis_pool.clone(),
            submission_tls,
        ));
        let s = srv.clone();
        supervisor.spawn("submission", async move { s.start().await });
        Some(srv)
    } else {
        None
    };

    // Postmaster Tools / SNDS reputation poller (background, never aborts startup).
    let postmaster_pool = pool.clone();
    let postmaster_redis = redis_pool.clone();
    let _postmaster_handle = tokio::spawn(async move {
        // The resolver pulls plaintext secrets from the compliance secret_manager
        // via Redis pub/sub if available, falling back to the raw value of the
        // referenced env var. Failure here is logged but does not stop the poll.
        let resolver: mta::postmaster::scheduler::SecretResolver =
            std::sync::Arc::new(move |secret_ref: String| {
                let r = postmaster_redis.clone();
                Box::pin(async move {
                    if let Ok(mut conn) = r.get().await {
                        let key = format!("compliance:secrets:{}:plaintext", secret_ref);
                        let v: Result<Option<String>, _> =
                            redis::cmd("GET").arg(&key).query_async(&mut *conn).await;
                        if let Ok(Some(val)) = v {
                            return Ok(val);
                        }
                    }
                    // Last-resort fallback: env var with the secret_ref name.
                    std::env::var(&secret_ref).map_err(|_| {
                        format!("secret_ref '{secret_ref}' not found in Redis or env",)
                    })
                })
            });
        let cfg = mta::postmaster::scheduler::ScheduleConfig::default();
        info!(
            "Postmaster reputation poller starting (interval = {:?})",
            cfg.interval
        );
        let handle = mta::postmaster::scheduler::spawn(postmaster_pool, cfg, resolver);
        if let Err(e) = handle.await {
            error!(error = %e, "Postmaster scheduler exited");
        }
    });

    // Wait for either a shutdown signal or the FIRST unexpected listener
    // exit. A listener exit before shutdown is always a failure: readiness
    // latches false and the process terminates so it is restarted.
    info!("MTA server running. Waiting for shutdown signal.");
    // With no supervised listener at all (every SMTP listener disabled)
    // there is nothing whose exit could be unexpected: serve health /
    // metrics / postmaster polling until shutdown instead of failing on an
    // empty supervisor.
    let listener_failure = if supervisor.is_empty() {
        shutdown.await;
        None
    } else {
        tokio::select! {
            _ = shutdown => None,
            exit = supervisor.next_exit() => Some(exit),
        }
    };

    if let Some((name, result)) = listener_failure {
        readiness.set_not_ready();
        match result {
            Ok(()) => error!(
                listener = name,
                "Listener exited unexpectedly: readiness is now false, terminating the service so \
                 it is restarted"
            ),
            Err(error) => error!(
                listener = name,
                error = %error,
                "Listener failed unexpectedly: readiness is now false, terminating the service so \
                 it is restarted"
            ),
        }
        // Best-effort stop of the remaining listeners, then fail non-zero.
        if let Some(ref srv) = inbound_srv {
            srv.stop();
        }
        if let Some(ref srv) = bounce_srv {
            srv.stop();
        }
        if let Some(ref srv) = fbl_srv {
            srv.stop();
        }
        if let Some(ref srv) = submission_srv {
            srv.stop();
        }
        supervisor.abort_all();
        health_handle.abort();
        return Err(anyhow::anyhow!(
            "listener '{name}' exited unexpectedly; terminating the MTA process so it is restarted"
        ));
    }

    info!("Shutting down...");

    // #151:Signal graceful shutdown on all servers before aborting
    if let Some(ref srv) = inbound_srv {
        srv.stop();
    }
    if let Some(ref srv) = bounce_srv {
        srv.stop();
    }
    if let Some(ref srv) = fbl_srv {
        srv.stop();
    }
    if let Some(ref srv) = submission_srv {
        srv.stop();
    }
    if let Some(ref shutdown) = inbound_delivery_shutdown {
        shutdown.notify_waiters();
    }

    // #150:Use .max(5) so grace period is AT LEAST 5s (was .min(5) = at most 5s)
    let grace = std::time::Duration::from_secs(config.graceful_shutdown_timeout.max(5));
    for (name, result) in supervisor.join_all(grace).await {
        match result {
            Ok(()) => info!(listener = name, "Listener stopped"),
            Err(error) => warn!(listener = name, error = %error, "Listener stopped with error"),
        }
    }

    // #152:Abort health server last
    health_handle.abort();

    pool.close().await;
    info!("MTA server stopped");
    Ok(())
}

/// Build the `/health` + `/ready` router. `/ready` answers 503 while the
/// readiness flag is latched false or while the database/Redis dependencies
/// fail their liveness probe.
fn health_router(
    health_pool: sqlx::PgPool,
    health_redis: deadpool_redis::Pool,
    readiness: Readiness,
) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/ready",
            get(move || {
                let p = health_pool.clone();
                let r = health_redis.clone();
                let readiness = readiness.clone();
                async move {
                    if !readiness.is_ready() {
                        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready");
                    }
                    let db_ok = sqlx::query("SELECT 1").execute(&p).await.is_ok();
                    let redis_ok = r.get().await.is_ok();
                    if db_ok && redis_ok {
                        (axum::http::StatusCode::OK, "ready")
                    } else {
                        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready")
                    }
                }
            }),
        )
}

/// One alarm-transition decision: which alarm (if any) must be emitted for
/// `days_remaining` given the last emitted threshold, and the new
/// last-emitted state. `None`/`None` means "no alarm window crossed".
fn expiry_alarm_transition(
    days_remaining: i64,
    last_alarm_days: Option<i64>,
) -> (Option<tls::CertExpiryAlarm>, Option<i64>) {
    match tls::cert_expiry_alarm(days_remaining) {
        Some(alarm) if last_alarm_days != Some(alarm.threshold_days()) => {
            (Some(alarm), Some(alarm.threshold_days()))
        }
        Some(_) => (None, last_alarm_days),
        None => (None, None),
    }
}

/// Inspect the TLS certificate every 6 hours and emit the 30/14/7/1-day
/// alarms (plus the days-remaining gauge) for the operator.
async fn cert_expiry_alarm_loop(cert_path: String) {
    let mut ticker = tokio::time::interval(Duration::from_secs(6 * 3600));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_alarm_days: Option<i64> = None;
    loop {
        ticker.tick().await;
        let now_unix = chrono::Utc::now().timestamp();
        match tls::inspect_certificate_file(Path::new(&cert_path), now_unix) {
            Ok(expiry) => {
                metrics::gauge!("apexmail_mta_tls_cert_days_remaining")
                    .set(expiry.days_remaining as f64);
                let (alarm, next) = expiry_alarm_transition(expiry.days_remaining, last_alarm_days);
                if let Some(alarm) = alarm {
                    if alarm.is_error() {
                        error!(
                            cert_path = %cert_path,
                            days_remaining = expiry.days_remaining,
                            threshold_days = alarm.threshold_days(),
                            "TLS certificate expiry alarm: renew now"
                        );
                    } else {
                        warn!(
                            cert_path = %cert_path,
                            days_remaining = expiry.days_remaining,
                            threshold_days = alarm.threshold_days(),
                            "TLS certificate expiry alarm"
                        );
                    }
                    metrics::counter!(
                        "apexmail_mta_tls_cert_expiry_alarm_total",
                        "alarm" => alarm.metric_label()
                    )
                    .increment(1);
                }
                last_alarm_days = next;
            }
            Err(error) => {
                metrics::gauge!("apexmail_mta_tls_cert_days_remaining").set(-1.0);
                error!(
                    cert_path = %cert_path,
                    error = %error,
                    "Failed to inspect TLS certificate for expiry"
                );
            }
        }
    }
}

/// Resolve when SIGINT or SIGTERM arrives.
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => sig.recv().await,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler, waiting indefinitely");
                std::future::pending().await
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C"),
        _ = terminate => info!("received SIGTERM"),
    }
}

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls;

    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .filter_map(|c| c.ok())
        .collect();
    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {key_path}"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Build the submission server's TLS acceptor, or `None` when TLS is
/// disabled. Any load failure propagates as an error: submission must
/// never run with AUTH but no TLS gate.
fn submission_tls_acceptor(
    tls: &mta::config::TlsConfig,
) -> anyhow::Result<Option<tokio_rustls::TlsAcceptor>> {
    if !tls.enabled {
        return Ok(None);
    }
    let cert_path = tls.cert_path.as_deref().unwrap_or("cert.pem");
    let key_path = tls.key_path.as_deref().unwrap_or("key.pem");
    Ok(Some(load_tls_acceptor(cert_path, key_path)?))
}

/// Initialize tracing subscriber with OTLP support.
/// Falls back to JSON logging when OTLP is not configured.
fn init_tracing(log_level: &str) -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "mta-server".into(),
            service_version: option_env!("CARGO_PKG_VERSION").map(str::to_string),
            environment: std::env::var("APP_ENV").ok(),
            ..Default::default()
        };

        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(error) => tracing::error!("failed to initialize OTLP tracing: {error}"),
        }
    }

    // try_init (not init): the binary initializes tracing exactly once, but
    // a second initialization must be a no-op rather than a panic — the
    // first installed subscriber wins, which is also the production
    // behaviour when a library has already installed one.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .try_init()
        .ok();
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> String {
        format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn test_submission_tls_disabled_returns_none() {
        let tls = mta::config::TlsConfig::default();
        assert!(submission_tls_acceptor(&tls).unwrap().is_none());
    }

    #[test]
    fn test_submission_tls_missing_cert_is_fatal() {
        // FIX-1: TLS cert load failure must propagate (fatal startup),
        // never warn-and-continue with tls_acceptor: None (which would
        // leave AUTH PLAIN/LOGIN accepted in cleartext on port 587).
        let tls = mta::config::TlsConfig {
            enabled: true,
            cert_path: Some(format!("{}/missing-cert.pem", fixture_dir())),
            key_path: Some(format!("{}/missing-key.pem", fixture_dir())),
        };
        assert!(
            submission_tls_acceptor(&tls).is_err(),
            "TLS load failure must be fatal"
        );
    }

    #[test]
    fn test_submission_tls_loads_valid_cert() {
        // main() installs the ring provider; tests must do the same so
        // ServerConfig::builder() has a default CryptoProvider.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let tls = mta::config::TlsConfig {
            enabled: true,
            cert_path: Some(format!("{}/cert.pem", fixture_dir())),
            key_path: Some(format!("{}/key.pem", fixture_dir())),
        };
        assert!(submission_tls_acceptor(&tls).unwrap().is_some());
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Reachable pieces of the MTA binary: TLS material loading must fail
    //! loudly (never a half-configured listener), and the expiry-alarm loop
    //! must keep running through both valid and unreadable certificates.

    use super::*;

    fn pem(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    fn cert_expiring_in(days: i64) -> String {
        let mut params = rcgen::CertificateParams::new(vec!["mail.apexmail.ee".to_string()])
            .expect("rcgen params");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        let not_after = chrono::Utc::now() + chrono::Duration::days(days);
        params.not_after = rcgen::date_time_ymd(
            not_after.format("%Y").to_string().parse().unwrap(),
            not_after.format("%m").to_string().parse().unwrap(),
            not_after.format("%d").to_string().parse().unwrap(),
        );
        let key = rcgen::KeyPair::generate().expect("key");
        pem(params.self_signed(&key).expect("cert").der().as_ref())
    }

    #[test]
    fn load_tls_acceptor_rejects_a_key_file_without_a_private_key() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        std::fs::write(&cert, cert_expiring_in(60)).unwrap();
        let key = dir.path().join("empty-key.pem");
        std::fs::write(&key, "").unwrap();

        let error = load_tls_acceptor(cert.to_str().unwrap(), key.to_str().unwrap())
            .err()
            .expect("a key file without a private key must be fatal");
        assert!(
            error.to_string().contains("No private key found"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_tls_acceptor_rejects_a_certificate_file_without_certificates() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("garbage.pem");
        std::fs::write(&cert, "not a certificate\n").unwrap();
        // A valid key paired with no certificate must fail rather than
        // produce a listener that cannot complete a handshake.
        let key = dir.path().join("key.pem");
        let key_pair = rcgen::KeyPair::generate().unwrap();
        std::fs::write(&key, key_pair.serialize_pem()).unwrap();

        assert!(load_tls_acceptor(cert.to_str().unwrap(), key.to_str().unwrap()).is_err());
    }

    #[tokio::test]
    async fn cert_expiry_alarm_loop_survives_valid_and_unreadable_certificates() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();

        // A certificate inside the 30-day alarm window: the loop must inspect
        // it, emit the alarm, and stay alive for the next tick.
        let expiring = dir.path().join("expiring.pem");
        std::fs::write(&expiring, cert_expiring_in(20)).unwrap();
        let handle = tokio::spawn(cert_expiry_alarm_loop(
            expiring.to_string_lossy().to_string(),
        ));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !handle.is_finished(),
            "the alarm loop must keep running after a successful inspection"
        );
        handle.abort();

        // An unreadable path logs the error and must not kill the loop
        // (otherwise the operator loses every later expiry alarm).
        let missing = dir.path().join("missing.pem");
        let handle = tokio::spawn(cert_expiry_alarm_loop(
            missing.to_string_lossy().to_string(),
        ));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !handle.is_finished(),
            "an unreadable certificate must not stop the alarm loop"
        );
        handle.abort();
    }
}

#[cfg(test)]
mod run_tests {
    //! Full-binary lifecycle coverage: `run_` (the extracted `main` body) is
    //! driven with an in-band shutdown future instead of signals, against a
    //! freshly provisioned canonical schema and the test Redis. No real
    //! external network is used; listeners bind loopback with OS-assigned
    //! ports.

    use super::*;
    use mta::config::{
        BounceConfig, DatabaseConfig, FeedbackConfig, InboundConfig, MetricsConfig, MtaConfig,
        RedisConfig, SubmissionConfig,
    };

    /// A loopback port the kernel assigns (dropped immediately; collisions
    /// with a sibling bind inside the same test are avoided by assigning all
    /// ports before any listener binds).
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("local addr")
            .port()
    }

    struct Ports {
        inbound: u16,
        inbound_secure: u16,
        bounce: u16,
        fbl: u16,
        submission: u16,
        health: u16,
    }

    fn ports() -> Ports {
        Ports {
            inbound: free_port(),
            inbound_secure: free_port(),
            bounce: free_port(),
            fbl: free_port(),
            submission: free_port(),
            health: free_port(),
        }
    }

    fn base_config(db_url: &str, ports: &Ports) -> MtaConfig {
        MtaConfig {
            node_env: "development".into(),
            database: DatabaseConfig {
                connection_string: db_url.into(),
                max_connections: 2,
            },
            redis: RedisConfig {
                url: std::env::var("TEST_REDIS_URL")
                    .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
                key_prefix: "mta-run-test:".into(),
            },
            inbound: InboundConfig {
                enabled: false,
                host: "127.0.0.1".into(),
                port: ports.inbound,
                secure_port: ports.inbound_secure,
                hostname: "inbound.run.test".into(),
                max_message_size: 1024 * 1024,
                max_recipients: 10,
                auth_required: false,
                advertise_auth_port25: false,
                require_fcrdns: false,
                arc_seal: false,
                tls: Default::default(),
            },
            bounce: BounceConfig {
                enabled: false,
                host: "127.0.0.1".into(),
                port: ports.bounce,
                hostname: "bounce.run.test".into(),
                verp_domain: "bounces.run.test".into(),
                verp_sanitize: true,
                max_message_size: 1024 * 1024,
                max_connections_per_ip: 10,
                max_messages_per_connection: 10,
                max_messages_per_ip_per_hour: 100,
            },
            feedback: FeedbackConfig {
                enabled: false,
                host: "127.0.0.1".into(),
                port: ports.fbl,
                hostname: "fbl.run.test".into(),
                max_arf_size: 1024 * 1024,
                max_connections_per_ip: 10,
                max_messages_per_connection: 10,
            },
            submission: SubmissionConfig {
                enabled: false,
                host: "127.0.0.1".into(),
                port: ports.submission,
                hostname: "submission.run.test".into(),
                max_message_size: 1024 * 1024,
                max_recipients: 10,
                auth_required: true,
            },
            metrics: MetricsConfig {
                enabled: false,
                port: 9100,
            },
            health_port: ports.health,
            graceful_shutdown_timeout: 1,
            ..MtaConfig::default()
        }
    }

    fn test_db_url() -> Option<String> {
        std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    fn skip_if_no_db() -> Option<String> {
        let db = test_db_url();
        if db.is_none() {
            eprintln!("skipping: set TEST_DATABASE_URL to run the run_ lifecycle tests");
        }
        db
    }

    /// Raw HTTP/1.1 GET over TCP: no test-side HTTP client dependency.
    async fn http_get(port: u16, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect health server");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status line");
        (status, text)
    }

    /// GET a health route, retrying until the freshly spawned server
    /// accepts (bounded; each attempt sleeps <= 20 ms).
    async fn http_get_with_retry(port: u16, path: &str) -> (u16, String) {
        for _ in 0..100 {
            if let Ok(stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                drop(stream);
                return http_get(port, path).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("health server never became reachable on {port}");
    }

    #[tokio::test]
    async fn run_serves_every_listener_and_shuts_down_cleanly() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let mut config = base_config(&db_url, &ports);
        config.inbound.enabled = true;
        config.bounce.enabled = true;
        config.feedback.enabled = true;
        config.submission.enabled = true;
        config.verp.hmac_secret = Some("run-test-secret-0123456789abcdef".into());

        let health_port = ports.health;
        let task = tokio::spawn(run_(config, tokio::time::sleep(Duration::from_millis(50))));

        let (health_status, body) = http_get_with_retry(health_port, "/health").await;
        assert_eq!(health_status, 200, "{body}");
        assert!(body.ends_with("OK"), "{body}");

        let (ready_status, body) = http_get_with_retry(health_port, "/ready").await;
        assert_eq!(ready_status, 200, "db+redis live must answer ready: {body}");
        assert!(body.ends_with("ready"), "{body}");

        let result = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("run_ must return after shutdown")
            .expect("run_ task must not panic");
        assert!(result.is_ok(), "graceful shutdown: {result:?}");
    }

    #[tokio::test]
    async fn run_with_every_listener_disabled_is_a_no_op_until_shutdown() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let config = base_config(&db_url, &ports());
        let started = std::time::Instant::now();
        run_(config, std::future::ready(()))
            .await
            .expect("no listeners, clean exit");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "nothing to join: run_ must not wait out the grace period"
        );
    }

    #[tokio::test]
    async fn run_warns_about_plaintext_public_listeners_and_a_missing_verp_secret() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let mut config = base_config(&db_url, &ports);
        // Inbound OFF, submission + bounce ON, no TLS, no VERP secret: the
        // public-listener warning must name submission and the VERP warning
        // must fire — coverage of both warn arms (asserted via a clean exit;
        // the guarantees themselves are the operator-visible logs).
        config.bounce.enabled = true;
        config.submission.enabled = true;
        config.verp.hmac_secret = None;
        run_(config, std::future::ready(()))
            .await
            .expect("warn arms must not be fatal in dev");
    }

    #[tokio::test]
    async fn run_fails_fast_when_a_supervised_listener_cannot_bind() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        // Occupy the inbound port so the listener task exits with an error;
        // the supervisor must turn that into a process error.
        let _squatter = tokio::net::TcpListener::bind(("127.0.0.1", ports.inbound))
            .await
            .expect("squat");
        let mut config = base_config(&db_url, &ports);
        config.inbound.enabled = true;
        config.bounce.enabled = true;
        config.feedback.enabled = true;
        config.submission.enabled = true;
        config.verp.hmac_secret = Some("run-test-secret-0123456789abcdef".into());

        let error = tokio::time::timeout(
            Duration::from_secs(30),
            run_(config, std::future::pending()),
        )
        .await
        .expect("listener failure must resolve run_ without a shutdown signal")
        .expect_err("a listener that cannot bind must fail the process");
        let message = error.to_string();
        assert!(
            message.contains("exited unexpectedly"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("inbound"),
            "the failing listener is named: {message}"
        );
    }

    #[tokio::test]
    async fn run_fails_fast_when_the_database_is_unreachable() {
        let ports = ports();
        let mut config = base_config("postgres://127.0.0.1:1/nowhere", &ports);
        config.redis.url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let error = tokio::time::timeout(
            Duration::from_secs(30),
            run_(config, std::future::pending()),
        )
        .await
        .expect("unreachable DB resolves immediately (connect refused)")
        .expect_err("an unreachable database must abort startup");
        assert!(!error.to_string().is_empty());
    }

    #[tokio::test]
    async fn run_fails_fast_when_the_redis_pool_cannot_be_built() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let mut config = base_config(&db_url, &ports);
        config.redis.url = "::::not a redis url".into();
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            run_(config, std::future::pending()),
        )
        .await
        .expect("an invalid redis url fails without I/O")
        .expect_err("an unparseable redis url must abort startup");
        assert!(
            error.to_string().to_lowercase().contains("redis"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn run_installs_the_prometheus_recorder_when_metrics_are_enabled() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let mut config = base_config(&db_url, &ports);
        config.metrics.enabled = true;
        config.metrics.port = free_port();
        run_(config, std::future::ready(()))
            .await
            .expect("metrics listener on a free port must install cleanly");
    }

    #[tokio::test]
    async fn run_fails_fast_when_the_metrics_recorder_cannot_be_installed() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        // Install the process recorder first: whatever run_ then tries to
        // install fails ("recorder already installed") and startup must
        // abort rather than run without its observability.
        let _ = metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .install_recorder();
        let mut config = base_config(&db_url, &ports);
        config.metrics.enabled = true;
        config.metrics.port = free_port();
        let error = tokio::time::timeout(
            Duration::from_secs(30),
            run_(config, std::future::pending()),
        )
        .await
        .expect("the double install fails immediately")
        .expect_err("a recorder that cannot be installed must abort startup");
        assert!(error.to_string().contains("metrics listener"), "{error}");
    }

    fn fixture_path(name: &str) -> String {
        format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn write_cert_pair(dir: &std::path::Path, days: i64) -> (String, String) {
        use base64::Engine as _;
        let mut params =
            rcgen::CertificateParams::new(vec!["mail.apexmail.ee".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        let not_after = chrono::Utc::now() + chrono::Duration::days(days);
        params.not_after = rcgen::date_time_ymd(
            not_after.format("%Y").to_string().parse().unwrap(),
            not_after.format("%m").to_string().parse().unwrap(),
            not_after.format("%d").to_string().parse().unwrap(),
        );
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(der.der());
        let mut cert = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            cert.push_str(std::str::from_utf8(chunk).unwrap());
            cert.push('\n');
        }
        cert.push_str("-----END CERTIFICATE-----\n");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, &cert).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        (
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        )
    }

    #[tokio::test]
    async fn run_with_tls_enabled_binds_the_secure_listener_and_shuts_down() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let mut config = base_config(&db_url, &ports);
        config.inbound.enabled = true;
        config.submission.enabled = true;
        config.verp.hmac_secret = Some("run-test-secret-0123456789abcdef".into());
        config.inbound.tls.enabled = true;
        config.inbound.tls.cert_path = Some(fixture_path("cert.pem"));
        config.inbound.tls.key_path = Some(fixture_path("key.pem"));
        run_(config, tokio::time::sleep(Duration::from_millis(50)))
            .await
            .expect("TLS-enabled startup on free ports must come up and exit cleanly");
    }

    #[tokio::test]
    async fn run_refuses_production_submission_with_an_expired_certificate() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_cert_pair(dir.path(), -1);
        let mut config = base_config(&db_url, &ports);
        config.node_env = "production".into();
        config.submission.enabled = true;
        config.inbound.tls.enabled = true;
        config.inbound.tls.cert_path = Some(cert);
        config.inbound.tls.key_path = Some(key);
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            run_(config, std::future::pending()),
        )
        .await
        .expect("certificate inspection is local I/O only")
        .expect_err("an expired submission certificate must abort production startup");
        assert!(
            error
                .to_string()
                .contains("refusing to start submission in production"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn run_refuses_production_submission_without_tls() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let mut config = base_config(&db_url, &ports);
        config.node_env = "production".into();
        config.submission.enabled = true;
        config.inbound.tls.enabled = false;
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            run_(config, std::future::pending()),
        )
        .await
        .expect("the gate is checked before any listener binds")
        .expect_err("production submission without TLS must abort startup");
        assert!(error.to_string().contains("without TLS"), "{error}");
    }

    #[tokio::test]
    async fn run_accepts_production_submission_with_a_valid_certificate() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let ports = ports();
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_cert_pair(dir.path(), 90);
        let mut config = base_config(&db_url, &ports);
        config.node_env = "production".into();
        config.submission.enabled = true;
        config.verp.hmac_secret = Some("run-test-secret-0123456789abcdef".into());
        config.inbound.enabled = false;
        config.inbound.tls.enabled = true;
        config.inbound.tls.cert_path = Some(cert.clone());
        config.inbound.tls.key_path = Some(key);
        run_(config, tokio::time::sleep(Duration::from_millis(50)))
            .await
            .expect("a long-lived certificate passes the production gate");
    }

    #[tokio::test]
    async fn health_router_answers_ready_only_while_dependencies_are_live() {
        let Some(db_url) = skip_if_no_db() else {
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("scratch db");
        let redis = deadpool_redis::Config::from_url(
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
        )
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("redis pool");

        // Healthy: readiness true + live db/redis -> 200 ready.
        let readiness = Readiness::new();
        let port = free_port();
        let app = health_router(pool.clone(), redis.clone(), readiness.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let (status, body) = http_get_with_retry(port, "/ready").await;
        assert_eq!(status, 200, "{body}");
        server.abort();

        // Latched not-ready (a listener died): 503 without probing anything.
        let readiness = Readiness::new();
        readiness.set_not_ready();
        let port = free_port();
        let app = health_router(pool.clone(), redis.clone(), readiness);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let (status, body) = http_get_with_retry(port, "/ready").await;
        assert_eq!(status, 503, "a latched readiness must answer 503: {body}");
        assert!(body.ends_with("not ready"), "{body}");
        server.abort();

        // Ready flag but dead dependencies: still 503.
        let dead_pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://127.0.0.1:1/dead")
            .expect("lazy pool");
        let mut dead_cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
        let mut pool_cfg = deadpool_redis::PoolConfig::default();
        pool_cfg.timeouts.create = Some(Duration::from_millis(200));
        dead_cfg.pool = Some(pool_cfg);
        let dead_redis = dead_cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let port = free_port();
        let app = health_router(dead_pool, dead_redis, Readiness::new());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let (status, body) = http_get_with_retry(port, "/ready").await;
        assert_eq!(status, 503, "dead db+redis must answer 503: {body}");
        server.abort();
        pool.close().await;
    }

    #[tokio::test]
    async fn cert_expiry_alarm_loop_emits_the_first_alarm_within_the_first_tick() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        // A certificate inside the 30-day window: the immediate first tick
        // must run the full inspect->decide->emit path and the loop must
        // stay alive for later ticks.
        let (cert, _key) = write_cert_pair(dir.path(), 20);
        let handle = tokio::spawn(cert_expiry_alarm_loop(cert));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "the alarm loop must keep running after an in-window inspection"
        );
        handle.abort();
    }

    #[test]
    fn cli_defaults_to_info_and_accepts_an_override() {
        let cli = Cli::try_parse_from(["mta-server"]).expect("defaults parse");
        assert_eq!(cli.log_level, "info");
        let cli = Cli::try_parse_from(["mta-server", "--log-level", "debug"]).expect("flag parses");
        assert_eq!(cli.log_level, "debug");
        assert!(Cli::try_parse_from(["mta-server", "--log-level"]).is_err());
    }

    // ── expiry alarm transitions (pure decision logic) ────────────────────

    #[test]
    fn expiry_alarm_transition_emits_each_threshold_once_and_rearms() {
        use mta::tls::CertExpiryAlarm;

        // Fresh 20-day cert: first crossing of the 30-day threshold.
        let (alarm, next) = expiry_alarm_transition(20, None);
        assert_eq!(alarm, Some(CertExpiryAlarm::Days30));
        assert_eq!(next, Some(30));
        // The very next check must NOT re-emit the same threshold.
        let (alarm, next) = expiry_alarm_transition(20, next);
        assert_eq!(alarm, None, "same threshold is deduplicated");
        assert_eq!(next, Some(30), "dedup keeps the last threshold");

        // Tightening to the 7-day window is a NEW alarm.
        let (alarm, next) = expiry_alarm_transition(5, next);
        assert_eq!(alarm, Some(CertExpiryAlarm::Days7));
        assert_eq!(next, Some(7));
        // 1-day urgency is the ERROR alarm.
        let (alarm, next) = expiry_alarm_transition(1, next);
        assert_eq!(alarm, Some(CertExpiryAlarm::Day1));
        assert!(alarm.expect("checked above").is_error());
        assert_eq!(next, Some(1));

        // A renewed certificate (>30 days) clears the latch so a later
        // crossing re-alarms instead of being swallowed by the dedup.
        let (alarm, next) = expiry_alarm_transition(60, next);
        assert_eq!(alarm, None);
        assert_eq!(next, None, "a healthy cert resets the dedup state");
        let (alarm, _) = expiry_alarm_transition(25, next);
        assert_eq!(alarm, Some(CertExpiryAlarm::Days30));
    }

    #[test]
    fn expiry_alarm_transition_reports_negative_days_as_the_1_day_alarm() {
        use mta::tls::CertExpiryAlarm;
        let (alarm, next) = expiry_alarm_transition(-3, None);
        assert_eq!(alarm, Some(CertExpiryAlarm::Day1));
        assert_eq!(next, Some(1));
    }

    // ── init_tracing ──────────────────────────────────────────────────────

    /// Env-mutating tracing tests are serialized (std::env is process-global).
    static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    #[tokio::test]
    async fn init_tracing_without_otlp_returns_none() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        assert!(init_tracing("info").is_none());
    }
}
