#![deny(unsafe_code)]
pub mod admin_routes;
pub mod annual_report;
pub mod audit_logger;
pub mod bootstrap;
pub mod breach_notification;
pub mod config;
pub mod content_scanner;
pub mod dsar_rate_limit;
pub mod dsr_outbox_flush;
pub mod entitlements;
pub mod estonia_ou;
pub mod filing_package;
pub mod filing_transport;
pub mod financial_analytics;
pub mod gdpr_automation;
pub mod governance;
pub mod hipaa;
pub mod ledger_sweep;
pub mod legal_archive;
pub mod obligations;
pub mod registry_monitor;
pub mod retention;
pub mod retention_classes;
pub mod retention_sweep;
pub mod risk_scoring;
pub mod routes;
pub mod secret_manager;
pub mod signing;
pub mod security_questionnaires;
pub mod soc2;
pub mod statutory_calendar;
pub mod tax_policy;
pub mod trust_portal;
pub mod tsd_ledger;
pub mod types;
pub mod vat_oss;
pub mod vat_vies;
pub mod xbrl_taxonomy;

/// Existence probe for optional source tables (estonia_ou queries payroll /
/// dividend / operating-cost stores that may be absent on a deployment).
/// Errors degrade to `false`; callers surface the missing store explicitly.
pub async fn table_exists_fn(db: &sqlx::PgPool, table: &str) -> anyhow::Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        )",
    )
    .bind(table)
    .fetch_one(db)
    .await?;
    Ok(exists)
}
