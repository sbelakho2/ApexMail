//! ApexMail Worker Processors — Rust implementation of queue-based background workers.
//!
//! This crate provides high-performance Rust implementations of the worker processors
//! that handle background tasks:analytics aggregation, email sending, reply classification,
//! and webhook delivery.
//!
//! ## Modules
//!
//! - [`analytics`] — Event aggregation and real-time stats (Redis counters + Postgres rollups)
//! - [`email`] — Email sending pipeline (SMTP/SES, DKIM, tracking, warmup)
//! - [`reply_handler`] — Pattern-based reply classification with Aho-Corasick
//! - [`webhook`] — Webhook delivery with SSRF protection and circuit breakers
//! - [`common`] — Shared types, database pools, circuit breakers, error handling

#![deny(unsafe_code)]
pub mod analytics;
pub mod common;
pub mod email;
pub mod reply_handler;
pub mod webhook;

// Re-export main processor types
pub use analytics::AnalyticsProcessor;
pub use common::{ProcessorConfig, ProcessorError, ProcessorResult};
pub use email::EmailProcessor;
pub use reply_handler::{classify, ReplyClassification, ReplyHandler};
pub use webhook::WebhookProcessor;

/// Single crate-wide lock serializing env-mutating tests.
///
/// `std::env` is process-global, and `cargo test` runs every test of this
/// crate's binary in ONE process on parallel threads. Per-module locks do not
/// exclude each other: `email::tracking` and `email::processor` both mutate
/// `TRACKING_SECRET_KEY`, so a module-local lock let one test re-set the
/// variable while another asserted its absence (ci/README.md §9 F10 — flaky
/// under `cargo test`, invisible under nextest's process isolation). Every
/// `#[cfg(test)]` module that calls `std::env::set_var`/`remove_var` must take
/// this lock for the duration of the mutation AND the assertion.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Cross-process guard for tests that touch SHARED Redis keyspaces
    /// (`rl:send:*` admission buckets, warmup counters keyed on real IPs):
    /// nextest runs each test in its own process, so only a Postgres advisory
    /// lock on the shared admin database can serialize them. Hold the
    /// returned pool for the test's lifetime (the lock is session-scoped).
    pub(crate) async fn redis_keys_guard(admin_url: &str, lock_name: &str) -> Option<sqlx::PgPool> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(admin_url)
            .await
            .ok()?;
        sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
            .bind(format!("worker-shared-redis:{lock_name}"))
            .execute(&pool)
            .await
            .ok()?;
        Some(pool)
    }

    /// Install a process-wide tracing subscriber for tests (idempotent).
    ///
    /// Without a subscriber the `tracing` macros short-circuit before their
    /// formatting regions run, so every `warn!`/`info!`/`error!`/`debug!`
    /// arm inside a production code path reports as never-executed even when
    /// the path itself is exercised. Installing a DEBUG-level subscriber
    /// makes those arms genuinely run (and count) while keeping `TRACE`
    /// noise (sqlx statement logs) filtered. Tests that exercise log-bearing
    /// paths call this first; `call_once` makes repeats a no-op, and the
    /// `Err` from a lost race with another thread's first install is
    /// intentionally ignored.
    pub(crate) fn install_test_tracing() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            use tracing_subscriber::EnvFilter;
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_new("debug").unwrap_or_else(|_| EnvFilter::new("debug")),
                )
                .with_test_writer()
                .try_init();
        });
    }
}
