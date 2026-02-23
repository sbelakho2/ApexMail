//! ApexMail Billing Service
//!
//! Handles usage metering, plan management, quota enforcement, invoice record
//! keeping, rate-limit tier management and billing event processing.
//!
//! Stripe webhook handling and direct Stripe API calls remain in the TypeScript
//! billing app (`apps/billing`). This crate owns the business logic and
//! database layer.

pub mod config;
pub mod invoices;
pub mod plans;
pub mod routes;
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
