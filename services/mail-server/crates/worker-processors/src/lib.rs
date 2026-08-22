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
}

// Re-export main processor types
pub use analytics::AnalyticsProcessor;
pub use common::{ProcessorConfig, ProcessorError, ProcessorResult};
pub use email::EmailProcessor;
pub use reply_handler::{classify, ReplyClassification, ReplyHandler};
pub use webhook::WebhookProcessor;
