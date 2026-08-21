//! ApexMail Billing Service
//!
//! Handles usage metering, plan management, quota enforcement, invoice record
//! keeping, rate-limit tier management and billing event processing.

#![deny(unsafe_code)]
/// **DEPRECATED** — Dedicated IP provisioning now lives in `api-server::ip_provider`.
/// This module is retained for backward compatibility only. All new code should
/// use `api_server::ip_provider::DedicatedIpProvider`.
pub mod accounting_export;
pub mod config;
pub mod credit_notes;
pub mod hetzner_ip_provider;
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
pub mod plans;
pub mod routes;
pub mod stripe_webhooks;
pub mod subscriptions;
pub mod types;
pub mod usage;
pub mod usage_ingest;
pub mod vat_emta;
pub mod vat_kmd;

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
