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
    let health_pool = pool.clone();
    let health_redis = redis_pool.clone();
    let health_readiness = readiness.clone();
    let health_port = config.health_port;
    // #152:Store health server handle for proper shutdown
    let health_handle = tokio::spawn(async move {
        let app = Router::new()
            .route("/health", get(|| async { "OK" }))
            .route(
                "/ready",
                get(move || {
                    let p = health_pool.clone();
                    let r = health_redis.clone();
                    let readiness = health_readiness.clone();
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
            );
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
    let listener_failure = tokio::select! {
        _ = wait_for_shutdown_signal() => None,
        exit = supervisor.next_exit() => Some(exit),
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
                match tls::cert_expiry_alarm(expiry.days_remaining) {
                    Some(alarm) if last_alarm_days != Some(alarm.threshold_days()) => {
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
                        last_alarm_days = Some(alarm.threshold_days());
                    }
                    Some(_) => {}
                    None => last_alarm_days = None,
                }
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

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .init();
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
