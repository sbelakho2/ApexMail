//! Observability service binary entry-point.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_redis::{Config as RedisConfig, Runtime};
use metrics_exporter_prometheus::PrometheusBuilder;
use observability_service::alerting::{AlertManager, AlertRule, ComparisonOperator};
use observability_service::config::ObservabilityConfig;
use observability_service::log_aggregator::LogAggregator;
use observability_service::metrics_collector::MetricsCollector;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use observability_service::redis_monitor::{RedisKeyMonitor, DEFAULT_POLL_INTERVAL_SECS};
use observability_service::routes::{self, AppState};
use observability_service::slo::SloMonitor;
use observability_service::trace_collector::TraceCollector;
use observability_service::types::AlertSeverity;
use tracing_subscriber::EnvFilter;

/// Strip credentials (e.g. the Redis password) from a URL, keeping only
/// `scheme://host:port/path`. Used whenever a connection URL is logged.
fn redact_url_credentials(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<redacted-url>".to_string();
    };
    // Credentials live only inside the authority component (before the
    // first '/'), separated from host:port by '@'.
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, after)| after)
        .unwrap_or(authority);
    format!("{scheme}://{host_port}{path}")
}

#[tokio::main]
async fn main() {
    let config = match ObservabilityConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Invalid observability configuration: {err}");
            std::process::exit(1);
        }
    };

    // ── Tracing ─────────────────────────────────────────────────────────

    let _otlp_guard = init_service_tracing(&config);

    tracing::info!(
        port = config.port,
        env = %config.environment,
        redis_host = %config.redis_host,
        redis_port = config.redis_port,
        redis_db = config.redis_db,
        "Starting observability service"
    );

    if let Err(err) = run(config, shutdown_signal()).await {
        tracing::error!(error = %err, "observability service terminated");
        std::process::exit(1);
    }
}

/// Install the OTLP pipeline when enabled, falling back to plain JSON stdout
/// logs. Extracted from `main` so the tracing selection is a single reviewable
/// unit (tests never call it: the global subscriber can only be set once per
/// process).
fn init_service_tracing(config: &ObservabilityConfig) -> Option<TracingGuard> {
    // When an OTLP endpoint is configured, install a registry that combines
    // JSON stdout logs with an OTLP span exporter (same pattern as every
    // other ApexMail service). Fall back to plain JSON logs otherwise.
    let _otlp_guard = if is_otlp_enabled() && config.tracing.enabled {
        match init_otlp_tracing(OtlpConfig {
            service_name: "observability-service".into(),
            service_version: Some(config.version.clone()),
            environment: Some(config.environment.clone()),
            ..Default::default()
        }) {
            Ok(guard) => Some(guard),
            Err(err) => {
                tracing::error!(error = %err, "failed to initialize OTLP tracing");
                None
            }
        }
    } else {
        None
    };
    if _otlp_guard.is_none() {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .json()
            .init();
    }
    _otlp_guard
}

/// Build the shared service state: collectors, pools, default SLOs and the
/// default alert rule set. Extracted from `main` so the wiring contract is
/// assertable without a live listener.
fn build_state(
    config: &ObservabilityConfig,
    redis_pool: Arc<deadpool_redis::Pool>,
    db_pool: Option<sqlx::PgPool>,
    metrics_collector: Arc<MetricsCollector>,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
) -> AppState {
    let state = AppState::new(
        metrics_collector,
        Arc::new(TraceCollector::new()),
        Arc::new(LogAggregator::new()),
        Arc::new(AlertManager::new()),
        Arc::new(SloMonitor::new()),
        config.internal_service_token.clone(),
    )
    .with_redis_pool(redis_pool)
    .with_metrics_handle(metrics_handle);

    let state = match db_pool {
        Some(pool) => {
            tracing::info!(
                db_url = %redact_url_credentials(&config.db_url()),
                "system_alerts persistence enabled (alertmanager alerts are mirrored to Postgres)"
            );
            state.with_db_pool(pool)
        }
        None => {
            tracing::warn!(
                "no Postgres pool — ingested alerts stay in-memory only (CP system_alerts surfaces will remain empty)"
            );
            state
        }
    };

    // ── Default SLOs ───────────────────────────────────────────────────

    state.slos.define_slo("api_availability", 99.9, 30);
    state.slos.define_slo("api_latency_p99", 99.0, 7);
    tracing::info!(slos = state.slos.list_slos().len(), "Defined default SLOs");

    // ── Default alert rules ────────────────────────────────────────────

    if config.alerting.enabled {
        state.alerts.add_rule(AlertRule {
            name: "high_redis_eviction_rate".into(),
            condition_description: "Redis eviction rate exceeds 100 keys/minute".into(),
            metric_name: "redis_eviction_rate_per_minute".into(),
            operator: ComparisonOperator::Gt,
            threshold: 100.0,
            severity: AlertSeverity::Warning,
            cooldown_secs: 300,
        });
        state.alerts.add_rule(AlertRule {
            name: "high_log_error_rate".into(),
            condition_description: "Aggregated log error rate exceeds 5% over 5 minutes".into(),
            metric_name: "observability_log_error_rate".into(),
            operator: ComparisonOperator::Gt,
            threshold: 0.05,
            severity: AlertSeverity::Critical,
            cooldown_secs: 600,
        });
        // Fired alerts are POSTed as JSON to every configured webhook
        // (ALERT_WEBHOOKS, comma-separated). Empty list disables dispatch.
        state
            .alerts
            .set_webhook_urls(config.alerting.webhook_urls.clone());
        tracing::info!(
            rules = state.alerts.list_rules().len(),
            webhooks = config.alerting.webhook_urls.len(),
            "Defined default alert rules"
        );
    }

    state
}

/// Spawn the periodic background tasks (Redis eviction monitor + self-metrics
/// and alert evaluation) and return the shared shutdown flag they observe.
fn spawn_background_tasks(
    state: &AppState,
    redis_pool: Arc<deadpool_redis::Pool>,
    metrics_collector: Arc<MetricsCollector>,
    alerting_enabled: bool,
    eval_interval_ms: u64,
) -> Arc<AtomicBool> {
    let eviction_monitor = Arc::new(RedisKeyMonitor::with_collector(
        None,
        metrics_collector.clone(),
    ));
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Spawn periodic Redis eviction check task
    let monitor_pool = redis_pool.clone();
    let monitor_clone = eviction_monitor.clone();
    let flag_clone = shutdown_flag.clone();
    tokio::spawn(async move {
        tracing::info!(
            poll_interval_secs = DEFAULT_POLL_INTERVAL_SECS,
            eviction_threshold = monitor_clone.eviction_rate_threshold(),
            "Redis key eviction monitor task started",
        );

        while !flag_clone.load(Ordering::Acquire) {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS)) => {
                    if flag_clone.load(Ordering::Acquire) {
                        break;
                    }
                    monitor_clone.check_evictions(&monitor_pool).await;
                }
            }
        }

        tracing::info!("Redis key eviction monitor task shut down");
    });

    // ── Periodic self-monitoring + alert evaluation task ───────────────

    let eval_state = state.clone();
    let eval_flag = shutdown_flag.clone();
    let eval_interval_ms = eval_interval_ms.max(1_000);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(eval_interval_ms));
        loop {
            ticker.tick().await;
            if eval_flag.load(Ordering::Acquire) {
                break;
            }

            let collector = eval_state.metrics.clone();
            collector.record_gauge(
                "observability_uptime_seconds",
                collector.uptime_secs() as f64,
                "Seconds since the observability service started",
            );
            let error_rate = eval_state.logs.get_error_rate(300);
            collector.record_gauge(
                "observability_log_error_rate",
                error_rate,
                "Error rate (errors / total) over the last 5 minutes of aggregated logs",
            );
            collector.record_gauge(
                "observability_traces_stored",
                eval_state.traces.len() as f64,
                "Number of trace spans currently retained",
            );
            collector.record_gauge(
                "observability_logs_stored",
                eval_state.logs.len() as f64,
                "Number of log entries currently retained",
            );
            collector.record_gauge(
                "observability_active_alerts",
                eval_state.alerts.list_active_alerts().len() as f64,
                "Number of currently firing alerts",
            );

            if alerting_enabled {
                let fired = eval_state.alerts.evaluate_all(&collector.get_summary());
                for alert in &fired {
                    tracing::warn!(
                        rule = %alert.rule_name,
                        severity = %alert.severity,
                        value = alert.value,
                        threshold = alert.threshold,
                        "ALERT FIRED"
                    );
                }
                if !fired.is_empty() {
                    // Fire-and-forget webhook dispatch (errors are logged
                    // inside; dispatch must never break the eval loop).
                    eval_state.alerts.dispatch_alerts(&fired).await;
                }
            }
        }
    });

    shutdown_flag
}

/// Resolve the listen address. G.2: the /metrics endpoint is unauthenticated,
/// so the server binds to loopback by default. Set METRICS_BIND_ADDR (e.g.
/// "0.0.0.0") to expose it on other interfaces — restrict access with
/// network policy. An invalid override falls back to loopback with a warning.
fn bind_addr(port: u16) -> SocketAddr {
    let bind_ip: std::net::IpAddr = std::env::var("METRICS_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1".to_string())
        .trim()
        .parse()
        .unwrap_or_else(|_| {
            tracing::warn!("invalid METRICS_BIND_ADDR — falling back to 127.0.0.1");
            std::net::IpAddr::from([127, 0, 0, 1])
        });
    SocketAddr::from((bind_ip, port))
}

/// Serve the observability service until `shutdown` resolves. Split out of
/// `main` so the startup sequence (recorder, pools, state wiring, background
/// tasks, bind, drain) is exercisable by tests with an injected shutdown —
/// production `main` passes [`shutdown_signal`]. Every refused startup
/// returns a descriptive `Err` that `main` turns into exit code 1.
async fn run(
    config: ObservabilityConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    // ── Global metrics recorder (backs the `metrics` crate used by the
    //    Redis monitor and rendered on `/metrics`) ──────────────────────

    let metrics_recorder = PrometheusBuilder::new().build_recorder();
    let metrics_handle = metrics_recorder.handle();
    if let Err(err) = metrics::set_global_recorder(Box::new(metrics_recorder)) {
        tracing::warn!(error = %err, "metrics recorder already installed");
    }

    // ── Redis connection pool ──────────────────────────────────────────

    let redis_url = config.redis_url();
    let redis_cfg = RedisConfig::from_url(&redis_url);
    let redis_pool = match redis_cfg.create_pool(Some(Runtime::Tokio1)) {
        Ok(pool) => Arc::new(pool),
        Err(err) => {
            // Never log the full URL — it embeds the percent-encoded Redis
            // password. Log only the scheme://host:port/db part.
            tracing::error!(
                error = %err,
                redis_url = %redact_url_credentials(&redis_url),
                "failed to create Redis pool"
            );
            return Err(format!("failed to create Redis pool: {err}"));
        }
    };

    // ── Postgres pool (system_alerts persistence) ──────────────────────
    // Lazy-connect: the alert ingest persists best-effort, so an initially
    // unreachable database degrades gracefully instead of failing startup.
    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.db_pool_max.min(5))
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(&config.db_url())
        .ok();

    // ── Core state ─────────────────────────────────────────────────────

    let default_buckets = config.metrics.histogram_buckets.clone();
    let metrics_collector = Arc::new(MetricsCollector::new(default_buckets));

    let state = build_state(
        &config,
        redis_pool.clone(),
        db_pool,
        metrics_collector.clone(),
        metrics_handle,
    );

    let shutdown_flag = spawn_background_tasks(
        &state,
        redis_pool,
        metrics_collector,
        config.alerting.enabled,
        config.metrics.aggregation_interval_ms,
    );

    // ── HTTP server ────────────────────────────────────────────────────

    let app = routes::router(state);

    let addr = bind_addr(config.port);
    tracing::info!(%addr, "Listening");

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|err| {
        tracing::error!(error = %err, %addr, "failed to bind listener");
        format!("failed to bind listener on {addr}: {err}")
    })?;

    let shutdown = {
        let flag = shutdown_flag.clone();
        async move {
            shutdown.await;
            tracing::info!("shutdown signal received — draining");
            flag.store(true, Ordering::Release);
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

/// Await SIGINT or SIGTERM, whichever arrives first.
async fn shutdown_signal() {
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
        _ = ctrl_c => {
            tracing::info!("received Ctrl+C — shutting down");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM — shutting down");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── redaction ──────────────────────────────────────────────────────

    #[test]
    fn redacts_password_from_redis_url() {
        assert_eq!(
            redact_url_credentials("redis://:p%40ss%3Aw@redis:6379/0"),
            "redis://redis:6379/0"
        );
    }

    #[test]
    fn redacts_user_and_password() {
        assert_eq!(
            redact_url_credentials("postgres://user:secret@db:5432/apexmail"),
            "postgres://db:5432/apexmail"
        );
    }

    #[test]
    fn keeps_credential_free_urls_untouched() {
        assert_eq!(
            redact_url_credentials("redis://127.0.0.1:6379/0"),
            "redis://127.0.0.1:6379/0"
        );
        assert_eq!(
            redact_url_credentials("http://otel-collector:4317/path"),
            "http://otel-collector:4317/path"
        );
    }

    #[test]
    fn redacts_unrecognizable_urls_to_a_placeholder() {
        assert_eq!(redact_url_credentials("not-a-url"), "<redacted-url>");
        assert_eq!(redact_url_credentials(""), "<redacted-url>");
    }

    // ── bind address selection (G.2 loopback default) ──────────────────

    #[test]
    fn bind_addr_defaults_to_loopback_and_honors_a_valid_override() {
        std::env::remove_var("METRICS_BIND_ADDR");
        assert_eq!(
            bind_addr(4400).to_string(),
            "127.0.0.1:4400",
            "/metrics is unauthenticated: the default bind must be loopback"
        );
        std::env::set_var("METRICS_BIND_ADDR", "  0.0.0.0  ");
        assert_eq!(bind_addr(4400).to_string(), "0.0.0.0:4400");
        // An invalid override must fall back to loopback, never crash.
        std::env::set_var("METRICS_BIND_ADDR", "not-an-ip");
        assert_eq!(bind_addr(4400).to_string(), "127.0.0.1:4400");
        std::env::remove_var("METRICS_BIND_ADDR");
    }

    // ── state wiring ───────────────────────────────────────────────────

    fn test_config(alerting: bool) -> ObservabilityConfig {
        let mut config = ObservabilityConfig {
            internal_service_token: "test-token".into(),
            ..ObservabilityConfig::default()
        };
        config.alerting.enabled = alerting;
        config
    }

    fn state_for(config: &ObservabilityConfig) -> AppState {
        let redis = Arc::new(
            deadpool_redis::Config::from_url(config.redis_url())
                .create_pool(Some(Runtime::Tokio1))
                .expect("redis pool"),
        );
        let collector = Arc::new(MetricsCollector::new(
            config.metrics.histogram_buckets.clone(),
        ));
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        build_state(config, redis, None, collector, handle)
    }

    #[test]
    fn build_state_defines_the_two_default_slos() {
        let state = state_for(&test_config(false));
        assert_eq!(state.slos.list_slos().len(), 2);
        assert_eq!(
            state.redis_pool.as_ref().expect("redis pool").status().size,
            0,
            "the pool is created lazily — nothing connects at startup"
        );
    }

    #[test]
    fn build_state_registers_default_alert_rules_only_when_alerting_is_enabled() {
        assert_eq!(
            state_for(&test_config(false)).alerts.list_rules().len(),
            0,
            "disabled alerting must not install rules"
        );
        let state = state_for(&test_config(true));
        assert_eq!(state.alerts.list_rules().len(), 2);
        let names: Vec<String> = state
            .alerts
            .list_rules()
            .iter()
            .map(|rule| rule.name.clone())
            .collect();
        assert!(
            names.contains(&"high_redis_eviction_rate".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"high_log_error_rate".to_string()),
            "{names:?}"
        );
    }

    // ── run(): process orchestration ───────────────────────────────────

    fn reserve_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("probe bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    /// Minimal HTTP/1.0 GET over a raw socket.
    async fn http_get(port: u16, path: &str) -> std::io::Result<(u16, String)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line")
            })?;
        Ok((status, text))
    }

    /// Full startup on an ephemeral port with the REAL local Redis: /health
    /// reports the dependency, /metrics renders the self-monitoring gauges
    /// the eval loop records on its first (immediate) tick, and the injected
    /// shutdown drains the listener before `run` returns.
    #[tokio::test]
    async fn run_serves_health_and_metrics_and_drains_on_shutdown() {
        let port = reserve_port();
        let mut config = ObservabilityConfig {
            port,
            internal_service_token: "test-token".into(),
            ..ObservabilityConfig::default()
        };
        // The eval loop's first tick is immediate; keep later ticks short so
        // the gauges refresh while the test polls.
        config.metrics.aggregation_interval_ms = 1_000;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run(config, async move {
            let _ = shutdown_rx.await;
        }));

        let mut health = None;
        for _ in 0..150 {
            if let Ok((200, body)) = http_get(port, "/health").await {
                health = Some(body);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let health = health.expect("the service must answer /health within 3s");
        assert!(health.to_lowercase().contains("ok"), "{health}");

        // The self-monitoring eval loop records gauges on its immediate
        // first tick; the /metrics scrape renders them via the recorder.
        let mut metrics_ok = false;
        for _ in 0..150 {
            if let Ok((200, body)) = http_get(port, "/metrics").await {
                if body.contains("observability_uptime_seconds") {
                    metrics_ok = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            metrics_ok,
            "/metrics must expose the self-monitoring gauges"
        );

        shutdown_tx.send(()).expect("service still running");
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("run must finish within 10s of shutdown")
            .expect("join");
        assert!(result.is_ok(), "clean drain: {result:?}");

        let rebinding = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(
            rebinding.is_ok(),
            "the drained service must release its port"
        );
    }

    /// Duplicate-instance conflict: a second instance on the same port must
    /// refuse to start with an error, not run half-alive.
    #[tokio::test]
    async fn run_refuses_to_start_when_the_port_is_taken() {
        let port = reserve_port();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("occupy the port");
        let config = ObservabilityConfig {
            port,
            internal_service_token: "test-token".into(),
            ..ObservabilityConfig::default()
        };
        let result = run(config, std::future::pending()).await;
        let error = result.expect_err("an occupied port must refuse startup");
        assert!(error.contains("failed to bind listener"), "error: {error}");
        drop(listener);
    }

    /// A broken Redis URL must refuse startup (exit 1 via main) instead of
    /// booting a service whose dependency checks can never run.
    #[tokio::test]
    async fn run_refuses_a_broken_redis_url() {
        let config = ObservabilityConfig {
            internal_service_token: "test-token".into(),
            redis_host: "bad host with spaces".into(),
            ..ObservabilityConfig::default()
        };
        let result = run(config, std::future::pending()).await;
        let error = result.expect_err("a broken redis URL must refuse startup");
        assert!(
            error.contains("failed to create Redis pool"),
            "error: {error}"
        );
    }

    /// SIGTERM (the container stop signal) must trigger the shutdown flag the
    /// background tasks observe — a plain ctrl_c-only service would leave the
    /// monitor and eval loops running until the process died.
    #[tokio::test]
    async fn shutdown_signal_fires_on_sigterm() {
        let task = tokio::spawn(shutdown_signal());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .output()
            .expect("kill utility");
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("shutdown_signal must complete on SIGTERM")
            .expect("join");
    }
}
