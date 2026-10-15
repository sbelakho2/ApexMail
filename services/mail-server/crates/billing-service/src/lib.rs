//! ApexMail Billing Service
//!
//! Handles usage metering, plan management, quota enforcement, invoice record
//! keeping, rate-limit tier management and billing event processing.

#![deny(unsafe_code)]
/// **DEPRECATED** — Dedicated IP provisioning now lives in `api-server::ip_provider`.
/// This module is retained for backward compatibility only. All new code should
/// use `api_server::ip_provider::DedicatedIpProvider`.
pub mod accounting_export;
/// Posting hooks into the statutory accounting ledger (migration 220).
pub mod accounting_postings;
pub mod adyen_webhooks;
pub mod config;
pub mod credit_notes;
pub mod invoices;
pub mod maintenance;
/// Monitoring and alerting for metering drain operations.
///
/// Wraps [`maintenance::drain_pending_metering_events`] with Prometheus-style
/// metrics (counters, gauges, histograms), consecutive-error alert thresholds,
/// and stale-event detection.
pub mod metering_monitor;
/// Money-invariant test gate (audit item 4): integer-cents round-trips,
/// half-up rounding everywhere, VAT line reconciliation, wallet
/// conservation, and a source-scan ban on f32/f64 in money paths.
#[cfg(test)]
mod money_invariants;
pub mod overage;
pub mod plans;
/// Contract product-line billing: the Platform line (base + per-1K usage
/// tier + active subaccounts above 100) and the Mailboxes seat line
/// (10-seat minimum, per-seat, archive add-on), billed monthly through the
/// shared period + invoice + collection machinery.
pub mod product_lines;
pub mod routes;
pub mod send_admission;
pub mod subscriptions;
/// Shared harness for in-crate adversarial coverage tests (private canonical
/// DB clones, schema fault injection, dead Redis pools, Adyen signing).
#[cfg(test)]
pub(crate) mod test_support;
pub mod types;
/// US sales tax (plan WP C2): economic-nexus threshold tracking plus the
/// provenance-stamped sales-tax line on US invoices for operator-registered
/// states only. Rates/thresholds come from the committed
/// `data/us_sales_tax.json` (validated, fail-closed on staleness); the module
/// never registers a state and never charges tax on its own.
pub mod us_tax;
pub mod usage;
pub mod usage_ingest;
pub mod vat_emta;
pub mod vat_kmd;
pub mod vat_recognition;

use std::sync::Arc;

use deadpool_redis::Pool as RedisPool;
use sqlx::PgPool;

/// Shared application state threaded through Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: RedisPool,
    pub config: config::BillingConfig,
}

impl AppState {
    pub fn new(db: PgPool, redis: RedisPool, config: config::BillingConfig) -> Arc<Self> {
        Arc::new(Self { db, redis, config })
    }
}
