//! ApexMail Billing Service
//!
//! Handles usage metering, plan management, quota enforcement, invoice record
//! keeping, rate-limit tier management and billing event processing.

pub mod config;
/// **DEPRECATED** — Dedicated IP provisioning now lives in `api-server::ip_provider`.
/// This module is retained for backward compatibility only. All new code should
/// use `api_server::ip_provider::DedicatedIpProvider`.
pub mod hetzner_ip_provider;
pub mod invoices;
pub mod maintenance;
pub mod plans;
pub mod routes;
mod stripe_webhooks;
pub mod subscriptions;
pub mod types;
pub mod usage;

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
