//! Billing service entry point.
//!
//! Reads configuration from environment variables (or `.env`), sets up the
//! database pool, Redis pool and HTTP server, then serves billing routes.

use clap::Parser;
use deadpool_redis::Runtime;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{fmt, EnvFilter};

use billing_service::{config::BillingConfig, maintenance, routes, AppState};

#[derive(Parser, Debug)]
#[command(name = "billing-service", about = "ApexMail billing service")]
struct Cli {
    /// Listen address (overrides BILLING_LISTEN_ADDR).
    #[arg(long, env = "BILLING_LISTEN_ADDR", default_value = "0.0.0.0:4100")]
    listen: String,

    /// Database URL.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Redis URL.
    #[arg(long, env = "REDIS_URL")]
    redis_url: String,

    /// Service auth token.
    #[arg(long, env = "SERVICE_AUTH_TOKEN", default_value = "")]
    service_auth_token: String,

    /// Mollie webhook signing secret.
    #[arg(long, env = "MOLLIE_API_KEY", default_value = "")]
    mollie_api_key: String,

    /// Internal API base URL.
    #[arg(long, env = "API_BASE_URL", default_value = "http://localhost:3001")]
    api_base_url: String,

    /// Reconcile the `plans` table with the canonical `platform-catalog`
    /// catalog, print the report and exit (one-shot ops entrypoint; the
    /// server reconciles on every boot anyway).
    #[arg(long, env = "BILLING_RECONCILE_PLANS_ONLY", default_value_t = false)]
    reconcile_plans_only: bool,

    /// Run the canonical end-of-period overage + PAYG sweep ONCE against the
    /// live database, print the report and exit (one-shot ops entrypoint;
    /// the scheduled sweep's first tick is the next UTC midnight, so an
    /// operator otherwise cannot close a period on demand, E-SWEEP-TRIGGER,
    /// live dogfood 2026-10-08).
    #[arg(long, env = "BILLING_SWEEP_OVERAGE_ONLY", default_value_t = false)]
    sweep_overage_only: bool,

    /// Run the contract product-line sweep (Platform + Mailboxes monthly
    /// invoices) ONCE against the live database, print the report and exit
    ///, the SAME function the nightly loop calls (one code path, one
    /// behavior; idempotent per tenant/line/month).
    #[arg(
        long,
        env = "BILLING_SWEEP_PRODUCT_LINES_ONLY",
        default_value_t = false
    )]
    sweep_product_lines_only: bool,

    /// Run the US sales-tax economic-nexus sweep ONCE against the live
    /// database, print the report and exit, the SAME function the nightly
    /// loop calls (one code path). Tracking and alerting only: it never
    /// registers a state and never charges tax.
    #[arg(long, env = "BILLING_SWEEP_US_TAX_NEXUS_ONLY", default_value_t = false)]
    sweep_us_tax_nexus_only: bool,

    /// Apply every period-end cancellation whose period has ended ONCE,
    /// print the count and exit, the SAME function the daily loop calls.
    /// The loop's first tick is 90 minutes after boot, so without this an
    /// operator cannot make a cancellation effective on demand.
    #[arg(
        long,
        env = "BILLING_END_CANCELED_SUBSCRIPTIONS_ONLY",
        default_value_t = false
    )]
    end_canceled_subscriptions_only: bool,

    /// Fetch every provider subscription this deployment holds and reconcile
    /// the local entitlement state ONCE, then exit, the SAME function the
    /// hourly loop calls. A subscription that is no longer `active` at Mollie
    /// (canceled, completed, suspended, pending) stops granting the plan; a
    /// subscription whose provider amount drifted from the catalog raises a
    /// finance incident. Operators use it after a provider-side change instead
    /// of waiting for the next hourly tick.
    #[arg(
        long,
        env = "BILLING_RECONCILE_SUBSCRIPTIONS_ONLY",
        default_value_t = false
    )]
    reconcile_subscriptions_only: bool,

    /// Validate the committed US sales-tax rate/threshold data file
    /// (`data/us_sales_tax.json`, or the `US_TAX_DATA_FILE` override),
    /// print the per-state freshness report and exit. Validation errors (and
    /// per-state nexus-declaration data errors) exit non-zero; no database is
    /// touched, this is the check to run after editing the file.
    #[arg(long, env = "BILLING_CHECK_US_TAX_DATA_ONLY", default_value_t = false)]
    check_us_tax_data_only: bool,

    /// Generate the filing-ready per-state US sales-tax report for one
    /// calendar month (`YYYY-MM`), print it and exit, the artifact the
    /// accountant consumes. The same generator the admin read
    /// (`GET /v1/admin/billing/us-tax/report?period=…`) serves.
    #[arg(long, env = "BILLING_US_TAX_REPORT")]
    us_tax_report: Option<String>,

    /// Output format of `--us-tax-report`: `json` (default) or `csv`.
    #[arg(long, env = "BILLING_US_TAX_REPORT_FORMAT", default_value = "json")]
    us_tax_report_format: String,
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "billing-service".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present (ignore errors).
    let _ = dotenvy::dotenv();

    let _guard = init_tracing();

    let cli = Cli::parse();

    tracing::info!(listen = %cli.listen, "starting billing-service");

    // US sales-tax data-file check (plan WP C2): a pure, DB-free ops
    // entrypoint, the operator runs it after editing
    // `data/us_sales_tax.json` (or a `US_TAX_DATA_FILE` override), before
    // deploying. Deliberately BEFORE any database or Redis connection so it
    // works anywhere the binary runs.
    if cli.check_us_tax_data_only {
        let today = chrono::Utc::now().date_naive();
        match billing_service::us_tax::check_data_file(today) {
            Ok(report) => {
                print!("{}", report.render());
                // A per-state nexus-declaration data error is a file defect
                // the operator must fix: the state is refused at evaluation
                // time, so the check exits non-zero for it too.
                if !report.declaration_errors.is_empty() {
                    std::process::exit(1);
                }
                return Ok(());
            }
            Err(error) => {
                eprintln!("US sales tax data file INVALID: {error}");
                std::process::exit(1);
            }
        }
    }

    // Database pool.
    let db = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&cli.database_url)
        .await?;

    // F1 (audit): bootstrap reconciliation, the `plans` table is converged
    // to the canonical `platform-catalog` catalog on every boot (insert
    // missing tiers, repair drifted prices/limits/features, deactivate
    // rows that are not catalog plans). Idempotent; mollie price ids
    // survive. The one-shot flag runs the same pass and exits, so ops can
    // converge a live deployment without a restart.
    let reconcile_report = billing_service::plans::reconcile_plans_with_catalog(&db).await?;
    tracing::info!(
        inserted = reconcile_report.inserted,
        repaired = reconcile_report.repaired,
        deactivated = reconcile_report.deactivated,
        "plans table reconciled with the canonical catalog"
    );
    if cli.reconcile_plans_only {
        println!(
            "plans reconcile: inserted={} repaired={} deactivated={}",
            reconcile_report.inserted, reconcile_report.repaired, reconcile_report.deactivated
        );
        return Ok(());
    }

    // E-SWEEP-TRIGGER: the on-demand overage sweep (the reconcile-plans
    // one-shot pattern). Deliberately BEFORE the Mollie webhook-secret
    // fail-fast: closing a period is an ops action that must work even when
    // the inbound webhook transport secret is absent, the sweep itself
    // needs only Postgres plus the Redis pool.
    if cli.sweep_overage_only {
        let redis =
            deadpool_redis::Config::from_url(&cli.redis_url).create_pool(Some(Runtime::Tokio1))?;
        let config = BillingConfig {
            database_url: cli.database_url,
            redis_url: cli.redis_url,
            listen_addr: cli.listen.clone(),
            service_auth_token: cli.service_auth_token,
            mollie_api_key: cli.mollie_api_key,
            api_base_url: cli.api_base_url,
            ..BillingConfig::default()
        };
        let state = AppState::new(db, redis, config);
        let result = maintenance::sweep_overage_once(state.as_ref())
            .await
            .map_err(anyhow::Error::msg)?;
        println!(
            "overage sweep: periods_checked={} invoices_created={} payg_invoices_created={} \
             wallet_paid={} pending_dunning={} skipped_no_address={} skipped_no_overage={} \
             skipped_unknown_plan={} failed_periods={} aged_needs_review={} \
             pricing_needs_review={} existing_invoice_mismatches={}",
            result.periods_checked,
            result.invoices_created,
            result.payg_invoices_created,
            result.wallet_paid,
            result.pending_dunning,
            result.skipped_no_address,
            result.skipped_no_overage,
            result.skipped_unknown_plan,
            result.failed_periods,
            result.aged_needs_review,
            result.pricing_needs_review,
            result.existing_invoice_mismatches,
        );
        return Ok(());
    }

    // The same one-shot ops pattern for the contract product lines
    // (Platform + Mailboxes): deliberately BEFORE the Mollie fail-fast for
    // the same reason, closing a contract month needs only Postgres plus
    // the Redis pool. Runs `maintenance::sweep_product_lines_once`, the
    // exact function the nightly loop calls.
    if cli.sweep_product_lines_only {
        let redis =
            deadpool_redis::Config::from_url(&cli.redis_url).create_pool(Some(Runtime::Tokio1))?;
        let config = BillingConfig {
            database_url: cli.database_url,
            redis_url: cli.redis_url,
            listen_addr: cli.listen.clone(),
            service_auth_token: cli.service_auth_token,
            mollie_api_key: cli.mollie_api_key,
            api_base_url: cli.api_base_url,
            ..BillingConfig::default()
        };
        let state = AppState::new(db, redis, config);
        let result = maintenance::sweep_product_lines_once(state.as_ref())
            .await
            .map_err(anyhow::Error::msg)?;
        println!(
            "product-lines sweep: tenants_checked={} tenant_months_checked={} \
             invoices_created={} periods_invoiced={} months_already_invoiced={} \
             periods_already_terminal={} skipped_no_address={} periods_needs_review={} \
             wallet_paid={} pending_dunning={} failed_months={}",
            result.tenants_checked,
            result.tenant_months_checked,
            result.invoices_created,
            result.periods_invoiced,
            result.months_already_invoiced,
            result.periods_already_terminal,
            result.skipped_no_address,
            result.periods_needs_review,
            result.wallet_paid,
            result.pending_dunning,
            result.failed_months,
        );
        return Ok(());
    }

    // The same one-shot ops pattern for the US sales-tax nexus sweep (plan
    // WP C2): tracking + alerting only (registration is an owner action and
    // no tax is charged here). Runs `maintenance::sweep_us_tax_nexus_once`,
    // the exact function the nightly loop calls.
    if cli.sweep_us_tax_nexus_only {
        let redis =
            deadpool_redis::Config::from_url(&cli.redis_url).create_pool(Some(Runtime::Tokio1))?;
        let config = BillingConfig {
            database_url: cli.database_url,
            redis_url: cli.redis_url,
            listen_addr: cli.listen.clone(),
            service_auth_token: cli.service_auth_token,
            mollie_api_key: cli.mollie_api_key,
            api_base_url: cli.api_base_url,
            ..BillingConfig::default()
        };
        let state = AppState::new(db, redis, config);
        let result = maintenance::sweep_us_tax_nexus_once(state.as_ref())
            .await
            .map_err(anyhow::Error::msg)?;
        println!(
            "us-tax nexus sweep: states_evaluated={} states_below={} states_crossed={} \
             states_registered={} states_not_taxable={:?} alerts_raised={} warnings_raised={} \
             states_warned={} without_threshold_data={:?} invalid_nexus_declarations={:?} \
             unknown_state_invoices={} unknown_state_cents={} non_usd_invoices={:?} \
             failed_states={}",
            result.states_evaluated,
            result.states_below,
            result.states_crossed,
            result.states_registered,
            result.states_not_taxable,
            result.alerts_raised,
            result.warnings_raised,
            result.states_warned,
            result.states_without_threshold_data,
            result.states_invalid_nexus,
            result.unknown_state_invoices,
            result.unknown_state_cents,
            result.non_usd_invoices,
            result.failed_states,
        );
        return Ok(());
    }

    // The filing-ready per-state US sales-tax report (plan WP C2): the
    // generator the accountant consumes, printed as JSON (default) or CSV.
    // Reads the database plus the rate file; it never writes anything.
    if let Some(period_raw) = cli.us_tax_report.as_deref() {
        let period = billing_service::us_tax::UsTaxReportPeriod::parse(period_raw)
            .map_err(anyhow::Error::msg)?;
        let format = cli.us_tax_report_format.trim().to_ascii_lowercase();
        if format != "json" && format != "csv" {
            anyhow::bail!(
                "--us-tax-report-format must be \"json\" or \"csv\", got {:?}",
                cli.us_tax_report_format
            );
        }
        let report = billing_service::us_tax::us_tax_report(&db, period, chrono::Utc::now())
            .await
            .map_err(anyhow::Error::msg)?;
        if format == "csv" {
            print!("{}", report.to_csv());
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&report.to_json()).map_err(anyhow::Error::msg)?
            );
        }
        return Ok(());
    }

    // The same one-shot ops pattern for provider subscription state: fetch
    // every `sub_…` row at Mollie and converge the local entitlement state.
    // Deliberately BEFORE the webhook fail-fast, reconciliation only needs
    // the API key the client reads from the environment, and an unconfigured
    // client reconciles nothing (0) instead of blocking ops.
    if cli.reconcile_subscriptions_only {
        let reconciled = billing_service::plan_billing::sweep_provider_subscription_state(&db)
            .await
            .map_err(anyhow::Error::msg)?;
        println!("subscription reconcile: reconciled={reconciled}");
        return Ok(());
    }

    if cli.end_canceled_subscriptions_only {
        let redis =
            deadpool_redis::Config::from_url(&cli.redis_url).create_pool(Some(Runtime::Tokio1))?;
        let config = BillingConfig {
            database_url: cli.database_url,
            redis_url: cli.redis_url,
            listen_addr: cli.listen.clone(),
            service_auth_token: cli.service_auth_token,
            mollie_api_key: cli.mollie_api_key,
            api_base_url: cli.api_base_url,
            ..BillingConfig::default()
        };
        let state = AppState::new(db, redis, config);
        let ended = maintenance::sweep_canceled_at_period_end(state.as_ref())
            .await
            .map_err(anyhow::Error::msg)?;
        println!("canceled-at-period-end sweep: ended={ended}");
        return Ok(());
    }

    // BS-001: Fail-fast if the Mollie key is not configured.
    // The /webhooks/mollie endpoint is exempt from service auth: the key IS
    // the authentication, because every webhook is verified by an
    // authenticated API fetch. Without it no event can ever be proven, so the
    // process refuses to start rather than silently drop billing events.
    if cli.mollie_api_key.trim().is_empty() {
        tracing::error!(
            "MOLLIE_API_KEY is not configured. Mollie webhooks are verified by \
             an authenticated API fetch, which requires this secret. Set the \
             environment variable or pass --mollie-api-key."
        );
        anyhow::bail!("MOLLIE_API_KEY is required");
    }

    // Migrations are managed externally (apexmail-db crate or deploy tooling).
    // If you need auto-migration, point sqlx::migrate! at the correct path.

    // BS-002: Validate that the dunning_config table exists at startup.
    // Previously the table was created on-demand at runtime (with a CREATE TABLE
    // IF NOT EXISTS in the webhook handler), which could cause race conditions
    // and obscures schema management.  Warn early if the migration is missing.
    {
        let table_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'dunning_config'
            )",
        )
        .fetch_one(&db)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check dunning_config table existence: {e}"))?;

        if !table_exists {
            tracing::warn!(
                "dunning_config table does not exist, dunning features will use \
                 hardcoded defaults. Run the database migrations to create this table."
            );
        } else {
            tracing::info!("dunning_config table found, dunning schema is up-to-date");
        }
    }

    // Redis pool.
    let redis_cfg = deadpool_redis::Config::from_url(&cli.redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1))?;

    // App state.
    let config = BillingConfig {
        database_url: cli.database_url,
        redis_url: cli.redis_url,
        listen_addr: cli.listen.clone(),
        service_auth_token: cli.service_auth_token,
        mollie_api_key: cli.mollie_api_key,
        api_base_url: cli.api_base_url,
        ..BillingConfig::default()
    };

    let state = AppState::new(db, redis, config);
    let app = routes::router(state.clone());
    maintenance::start_periodic_jobs(state.clone());
    billing_service::mollie_webhooks::spawn_deadletter_retry_worker(state.clone());

    // Bind & serve.
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!("billing-service listening on {}", cli.listen);

    let shutdown = async {
        let ctrl_c = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => tracing::info!("received Ctrl+C, shutting down"),
                Err(e) => {
                    tracing::error!("failed to install Ctrl+C handler: {e}");
                    std::future::pending::<()>().await;
                }
            }
        };
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => tokio::select! {
                    _ = ctrl_c => {}
                    _ = terminate.recv() => tracing::info!("received SIGTERM, shutting down"),
                },
                Err(e) => {
                    tracing::error!(
                        "failed to install SIGTERM handler: {e}; falling back to Ctrl+C only"
                    );
                    ctrl_c.await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await;
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}
