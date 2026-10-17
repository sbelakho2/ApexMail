#![deny(unsafe_code)]

pub mod admin_routes;
pub mod annual_report;
pub mod audit_logger;
pub mod bootstrap;
pub mod breach_notification;
pub mod claims_registry;
pub mod config;
pub mod consent_enforcement;
// The consent-expiry sweep (P3: batched + set-based). It previously existed as
// an orphan file — no `mod` declaration anywhere in the workspace — so it never
// compiled, never ran, and could not be tested. Declaring it here makes the
// sweep reachable (the job is started by an owner process, exactly like before).
pub mod consent_expiry;
pub mod content_scanner;
pub mod control_mappings;
pub mod deployment_products;
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
pub mod legal_hold;
pub mod obligations;
/// Procurement document index (the package a US customer's procurement
/// review asks for). Carries the US DPA addendum as a DRAFT row until the
/// owner approves it — never as an available artifact.
pub mod procurement_package;
pub mod registry_monitor;
pub mod retention;
pub mod retention_classes;
pub mod retention_sweep;
pub mod risk_scoring;
pub mod routes;
pub mod secret_manager;
pub mod security_questionnaires;
pub mod signing;
pub mod soc2;
pub mod statutory_calendar;
pub mod statutory_routes;
pub mod suppressions;
pub mod tax_policy;
pub mod trust_portal;
pub mod tsd_ledger;
pub mod types;
pub mod vat_oss;
pub mod vat_vies;
pub mod xbrl_taxonomy;

#[cfg(test)]
pub mod test_support;

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
