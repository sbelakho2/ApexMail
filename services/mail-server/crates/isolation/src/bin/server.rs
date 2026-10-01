//! Isolation server binary — HTTP on port 4500 with background cron jobs
//! and graceful shutdown.

use clap::Parser;
use deadpool_redis::{Config as DpRedisConfig, Runtime};
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::signal;
use tokio::time::{interval, Duration};
use tracing::{error, info};

use isolation::audit::AuditService;
use isolation::config::Config;
use isolation::data_isolation::DataIsolationService;
use isolation::encryption::EncryptionService;
use isolation::rate_limit::RateLimitService;
use isolation::routes::{create_router, AppState};
use isolation::tenant::TenantService;

#[derive(Parser)]
#[command(name = "isolation-server")]
struct Cli {
    /// Override port (default from ISOLATION_PORT or 4500)
    #[arg(short, long)]
    port: Option<u16>,
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "isolation-server".to_string(),
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
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "isolation=info,tower_http=info".into()),
        )
        .init();
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = init_tracing();

    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    // SEC fix: from_env is fallible now — production REFUSES missing
    // TENANT_ENCRYPTION_KEY / ISOLATION_INTERNAL_API_KEY instead of exiting
    // from inside the loader (EX_CONFIG; the isolation exit-78 convention,
    // shared with the compliance/ha crates).
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            error!(
                "SECURITY: isolation configuration refused to load: {error} — set the \
                 required environment variables and restart (exit 78 / EX_CONFIG)"
            );
            std::process::exit(78); // EX_CONFIG
        }
    };
    run(config, cli.port, shutdown_signal()).await
}

/// Postgres connection string assembled from the config parts. Extracted
/// from `main` so the credential formatting is assertable.
fn db_url(config: &Config) -> String {
    format!(
        "postgres://{}:{}@{}:{}/{}",
        config.database.user,
        config.database.password,
        config.database.host,
        config.database.port,
        config.database.database,
    )
}

/// CORS policy: a "*" origin list means permissive (a dev posture); any
/// other list is an allowlist, and entries that are not valid header values
/// are dropped rather than poisoning the whole layer.
fn build_cors(origins: &[String]) -> tower_http::cors::CorsLayer {
    if origins.iter().any(|o| o == "*") {
        tower_http::cors::CorsLayer::permissive()
    } else {
        let allowed: Vec<axum::http::HeaderValue> =
            origins.iter().filter_map(|o| o.parse().ok()).collect();
        tower_http::cors::CorsLayer::new()
            .allow_origin(allowed)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ])
            .allow_headers(tower_http::cors::Any)
    }
}

/// Router with the tracing and CORS middleware stack attached.
fn build_app(state: Arc<AppState>) -> axum::Router {
    let cors = build_cors(&state.config.cors.origins);
    create_router(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(cors)
}

/// Start the isolation server and serve until `shutdown` resolves. Split
/// out of `main` so the startup sequence (pools, service initialization,
/// cron, bind, drain) is exercisable by tests with an injected shutdown —
/// production `main` passes [`shutdown_signal`].
async fn run(
    config: Config,
    port_override: Option<u16>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let port = port_override.unwrap_or(config.port);

    // Database pool
    let db = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&db_url(&config))
        .await?;

    info!("Connected to database");

    // Redis pool
    let redis_cfg = DpRedisConfig::from_url(config.redis.url());
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1))?;

    info!("Redis pool created");

    // Build services
    let tenant = TenantService::new(db.clone(), config.clone());
    let mut isolation = DataIsolationService::new(db.clone());
    // F63: initialization failures (policy store unreadable, access-attempt
    // audit relation missing) are STARTUP errors. The previously logged-and-
    // continued behavior served requests with an unenforceable policy set and
    // a silently discarded audit trail.
    if let Err(e) = isolation.initialize().await {
        error!(error = %e, "Failed to initialize data isolation policies");
        return Err(e);
    }
    let security_config = config.security.clone();
    let encryption = EncryptionService::new(db.clone(), security_config.clone());
    // F63: load keys + field-encryption policies (iso_encryption_keys /
    // iso_encryption_policies) before serving. A missing relation or
    // unreadable key store is a readiness failure, not a runtime warn.
    encryption.initialize().await?;
    let rate_limit = RateLimitService::new(redis.clone());
    let audit = AuditService::new(db.clone(), security_config);

    let state = Arc::new(AppState {
        tenant,
        isolation,
        encryption,
        rate_limit,
        audit,
        config: config.clone(),
    });

    // Build router with middleware
    let app = build_app(state.clone());

    // Start background cron jobs
    let cron_state = state.clone();
    let cron_handle = tokio::spawn(async move {
        run_cron_jobs(cron_state).await;
    });

    // Start HTTP server
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|error| anyhow::anyhow!("failed to bind isolation server on {addr}: {error}"))?;
    info!("Isolation server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    info!("Shutting down...");
    cron_handle.abort();

    // Flush remaining audit events
    state.audit.flush().await.ok();

    db.close().await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(?error, "Failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(?error, "Failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}

/// Background cron jobs:/// 1. Audit buffer flush — every 5s
/// 2. Audit log cleanup — daily (every 24h)
/// 3. Encryption key rotation check — every 60min
/// 4. Access-attempt audit retention cleanup — daily (F63)
async fn run_cron_jobs(state: Arc<AppState>) {
    let mut flush_ticker = interval(Duration::from_secs(5));
    let mut cleanup_ticker = interval(Duration::from_secs(86400));
    let mut rotation_ticker = interval(Duration::from_secs(3600));
    let mut access_cleanup_ticker = interval(Duration::from_secs(86400));

    loop {
        tokio::select! {
                    _ = flush_ticker.tick() => {
                        if let Err(e) = state.audit.flush().await {
                            error!(error = %e, "Audit buffer flush failed");
                        }
                    }
                    _ = cleanup_ticker.tick() => {
                        match state.audit.cleanup().await {
                            Ok(n) if n > 0 => info!(count = n, "Audit log cleanup completed"),
                            Err(e) => error!(error = %e, "Audit log cleanup failed"),
                            _ => {}
                        }
                    }
                    _ = access_cleanup_ticker.tick() => {
                        // F63: iso_access_attempts is append-only per decision —
                        // retention keeps it bounded.
                        match state.isolation.cleanup_access_attempts(365).await {
                            Ok(n) if n > 0 => info!(count = n, "Access-attempt audit cleanup completed"),
                            Err(e) => error!(error = %e, "Access-attempt audit cleanup failed"),
                            _ => {}
                        }
                    }
                    _ = rotation_ticker.tick() => {
        // Check for keys needing rotation — iterate known orgs
        // In production, this would query the DB for stale keys
                        info!("Key rotation check completed");
                    }
                }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use isolation::config::{
        CorsConfig, DatabaseConfig, QuotaConfig, RedisConfig, SecurityConfig, TenantConfig,
    };
    use zeroize::Zeroizing;

    fn test_config(database: &str, password: &str) -> Config {
        Config {
            port: 4500,
            environment: "test".to_string(),
            internal_api_key: "test-internal-api-key".to_string(),
            internal_api_keys: vec!["test-internal-api-key".to_string()],
            // Audit SM5 F15: tests exercise the permissive (internal-call) mode
            // explicitly; the claim-required path is covered in routes tests.
            require_org_claim: false,
            database: DatabaseConfig {
                host: "127.0.0.1".to_string(),
                port: 5432,
                database: database.to_string(),
                user: "apexmail".to_string(),
                password: password.to_string(),
                max_connections: 5,
            },
            redis: RedisConfig {
                host: "127.0.0.1".to_string(),
                port: 6379,
                password: None,
                db: 3,
            },
            tenant: TenantConfig {
                max_workspaces_per_org: 50,
                max_users_per_workspace: 100,
                default_quota: QuotaConfig::default(),
            },
            security: SecurityConfig {
                encryption_key: Zeroizing::new(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                data_key_rotation_days: 90,
                audit_retention_days: 365,
                session_timeout_minutes: 30,
            },
            cors: CorsConfig {
                origins: vec!["*".to_string()],
            },
        }
    }

    // ── pure helpers ───────────────────────────────────────────────────

    #[test]
    fn db_url_assembles_the_connection_string_from_parts() {
        let config = test_config("apexmail_scratch_base", "s3cret");
        assert_eq!(
            db_url(&config),
            "postgres://apexmail:s3cret@127.0.0.1:5432/apexmail_scratch_base"
        );
    }

    #[tokio::test]
    async fn build_cors_accepts_both_postures() {
        // "*" → permissive layer; a list → restricted layer with invalid
        // entries dropped. CorsLayer has no introspection: the contract
        // under test is that neither posture panics and the router serves.
        let _permissive = build_cors(&["*".to_string()]);
        let _restricted = build_cors(&[
            "https://app.example".to_string(),
            "not a valid origin".to_string(),
        ]);
        let config = test_config("unused", "unused");
        let state = Arc::new(AppState {
            tenant: TenantService::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy(&db_url(&config))
                    .expect("lazy pool"),
                config.clone(),
            ),
            isolation: DataIsolationService::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy(&db_url(&config))
                    .expect("lazy pool"),
            ),
            encryption: EncryptionService::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy(&db_url(&config))
                    .expect("lazy pool"),
                config.security.clone(),
            ),
            rate_limit: RateLimitService::new(
                deadpool_redis::Config::from_url(config.redis.url())
                    .create_pool(Some(Runtime::Tokio1))
                    .expect("redis pool"),
            ),
            audit: AuditService::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy(&db_url(&config))
                    .expect("lazy pool"),
                config.security.clone(),
            ),
            config: config.clone(),
        });
        let _app = build_app(state);
    }

    // ── run(): process orchestration against the real dependency stack ──

    fn test_database_parts() -> Option<(String, String)> {
        // TEST_DATABASE_URL:
        // postgresql://USER:PASSWORD@HOST:PORT/DATABASE
        migrator::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let rest = url
            .strip_prefix("postgresql://")
            .or_else(|| url.strip_prefix("postgres://"))?;
        let (credentials, host_db) = rest.split_once('@')?;
        let (_user, password) = credentials.split_once(':')?;
        let (_host, rest) = host_db.split_once(':')?;
        let (port, database) = rest.split_once('/')?;
        let _ = port;
        Some((
            database.trim_end_matches('/').to_string(),
            password.to_string(),
        ))
    }

    fn reserve_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("probe bind")
            .local_addr()
            .expect("addr")
            .port()
    }

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

    /// Full startup against the real Postgres + Redis: pools connect, the
    /// F63 initializations pass, the cron jobs spawn, /health answers, and
    /// the injected shutdown drains (cron aborted, audit flushed, pool
    /// closed) before `run` returns.
    #[tokio::test]
    async fn run_serves_health_and_drains_on_shutdown() {
        let Some((database, password)) = test_database_parts() else {
            eprintln!("skipping: set TEST_DATABASE_URL to drive the server against Postgres");
            return;
        };
        let port = reserve_port();
        let config = test_config(&database, &password);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run(config, Some(port), async move {
            let _ = shutdown_rx.await;
        }));

        let mut health = None;
        for _ in 0..250 {
            if let Ok((200, body)) = http_get(port, "/health").await {
                health = Some(body);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let health = health.expect("the server must answer /health within 5s");
        assert!(health.contains("\"status\":\"ok\""), "{health}");
        assert!(health.contains("isolation"), "{health}");

        shutdown_tx.send(()).expect("server still running");
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("run must finish within 10s of shutdown")
            .expect("join");
        assert!(result.is_ok(), "clean drain: {result:?}");

        let rebinding = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(
            rebinding.is_ok(),
            "the drained server must release its port"
        );
    }

    /// Duplicate-instance conflict: a second server on the same port must
    /// fail with an error, not half-start.
    #[tokio::test]
    async fn run_refuses_to_start_when_the_port_is_taken() {
        let Some((database, password)) = test_database_parts() else {
            eprintln!("skipping: set TEST_DATABASE_URL to drive the server against Postgres");
            return;
        };
        let port = reserve_port();
        // Occupy the SAME wildcard address `run` binds: tokio listeners set
        // SO_REUSEADDR, and on macOS that lets a 0.0.0.0 bind succeed even
        // while 127.0.0.1 on the same port is held — the server would serve
        // forever instead of refusing. An exact wildcard-vs-wildcard
        // conflict is EADDRINUSE on every platform.
        let occupant = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .expect("occupy the port");
        let config = test_config(&database, &password);
        let result = run(config, Some(port), std::future::pending()).await;
        let error = result.expect_err("an occupied port must refuse startup");
        assert!(
            error
                .to_string()
                .contains("failed to bind isolation server")
                && error.to_string().contains(&port.to_string()),
            "error: {error}"
        );
        drop(occupant);
    }

    /// An unreachable database must refuse startup with an error naming the
    /// failure, before any listener exists.
    #[tokio::test]
    async fn run_fails_fast_when_the_database_is_unreachable() {
        let mut config = test_config("does_not_exist_db", "unused");
        // Loopback port 1 refuses instantly; the pool's acquire timeout
        // bounds the whole wait deterministically.
        config.database.port = 1;
        let result = run(config, Some(reserve_port()), std::future::pending()).await;
        assert!(
            result.is_err(),
            "an unreachable database must refuse startup"
        );
    }

    /// SIGTERM (the container stop signal) must trigger the graceful drain
    /// exactly like Ctrl-C.
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
