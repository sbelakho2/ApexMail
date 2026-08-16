//! Observability service binary entry-point.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_redis::{Config as RedisConfig, Runtime};
use metrics_exporter_prometheus::PrometheusBuilder;
use observability_service::alerting::{AlertManager, ComparisonOperator, AlertRule};
use observability_service::config::ObservabilityConfig;
use observability_service::log_aggregator::LogAggregator;
use observability_service::metrics_collector::MetricsCollector;
use observability_service::otlp_exporter::{init_otlp_tracing, is_otlp_enabled, OtlpConfig};
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

#[cfg(test)]
mod tests {
    use super::redact_url_credentials;

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
        assert_eq!(redact_url_credentials("redis://127.0.0.1:6379/0"), "redis://127.0.0.1:6379/0");
        assert_eq!(
            redact_url_credentials("http://otel-collector:4317/path"),
            "http://otel-collector:4317/path"
        );
    }
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

    tracing::info!(
        port = config.port,
        env = %config.environment,
        redis_host = %config.redis_host,
        redis_port = config.redis_port,
        redis_db = config.redis_db,
        "Starting observability service"
    );

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
            std::process::exit(1);
        }
    };

    // ── Core state ─────────────────────────────────────────────────────

    let default_buckets = config.metrics.histogram_buckets.clone();
    let metrics_collector = Arc::new(MetricsCollector::new(default_buckets));

    let state = AppState::new(
        metrics_collector.clone(),
        Arc::new(TraceCollector::new()),
        Arc::new(LogAggregator::new()),
        Arc::new(AlertManager::new()),
        Arc::new(SloMonitor::new()),
        config.internal_service_token.clone(),
    )
    .with_redis_pool(redis_pool.clone())
    .with_metrics_handle(metrics_handle);

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

    // ── Redis key eviction monitor ─────────────────────────────────────

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
    let alerting_enabled = config.alerting.enabled;
    let eval_flag = shutdown_flag.clone();
    let eval_interval_ms = config.metrics.aggregation_interval_ms.max(1_000);
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

    // ── HTTP server ────────────────────────────────────────────────────

    let app = routes::router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!(%addr, "Listening");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, %addr, "failed to bind listener");
            std::process::exit(1);
        }
    };

    let shutdown = {
        let flag = shutdown_flag.clone();
        async move {
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
                    flag.store(true, Ordering::Release);
                }
                _ = terminate => {
                    tracing::info!("received SIGTERM — shutting down");
                    flag.store(true, Ordering::Release);
                }
            }
        }
    };
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!(error = %err, "server error");
    }
}
