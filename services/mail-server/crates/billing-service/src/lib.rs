//! ApexMail Billing Service
//!
//! Handles usage metering, plan management, quota enforcement, invoice record
//! keeping, rate-limit tier management and billing event processing.

#![deny(unsafe_code)]
/// **DEPRECATED**, Dedicated IP provisioning now lives in `api-server::ip_provider`.
/// This module is retained for backward compatibility only. All new code should
/// use `api_server::ip_provider::DedicatedIpProvider`.
pub mod accounting_export;
/// Posting hooks into the statutory accounting ledger (migration 220).
pub mod accounting_postings;
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
pub mod mollie_client;
pub mod mollie_webhooks;
/// Money-invariant test gate (audit item 4): integer-cents round-trips,
/// half-up rounding everywhere, VAT line reconciliation, wallet
/// conservation, and a source-scan ban on f32/f64 in money paths.
#[cfg(test)]
mod money_invariants;
pub mod overage;
/// The provider-neutral payments domain (external audit, P0-A): the
/// [`payments::PaymentProvider`] boundary every billing decision speaks to,
/// the neutral state machines and fact types above it, and the Mollie
/// adapter plus fail-closed registry below it. Nothing neutral in here
/// names a provider id grammar; see `src/payments/NEUTRALITY_DEBT.md` for
/// the couplings deliberately kept this round and the steps that remove
/// them.
pub mod payments;
pub mod plan_billing;
pub mod plans;
/// Contract product-line billing: the Platform line (base + per-1K usage
/// tier + active subaccounts above 100), the Mailboxes seat line (10-seat
/// minimum, per-seat, archive add-on), the flat compliance/placement/EU-only
/// lines, and the Dedicated Tenant line (catalog monthly list + a one-time
/// setup fee with the first billed period + the contracted minimum term),
/// billed monthly through the shared period + invoice + collection machinery.
pub mod product_lines;
pub mod routes;
pub mod send_admission;
pub mod subscriptions;
/// The V30 list-price VAT rule: persist the buyer's declaration, verify VIES
/// evidence before the payment exists, and re-resolve at every tax point.
pub mod tax;
/// Shared harness for in-crate adversarial coverage tests (private canonical
/// DB clones, schema fault injection, dead Redis pools, Mollie signing).
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
