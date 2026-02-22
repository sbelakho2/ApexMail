//! ApexMail Worker Processors — Rust implementation of queue-based background workers.
//!
//! This crate provides high-performance Rust implementations of the worker processors
//! that handle background tasks: analytics aggregation, email sending, reply classification,
//! and webhook delivery.
//!
//! ## Modules
//!
//! - [`analytics`] — Event aggregation and real-time stats (Redis counters + Postgres rollups)
//! - `email` — Email sending pipeline (SMTP/SES, DKIM, tracking, warmup)
//! - `reply_handler` — AI/pattern-based reply classification (Aho-Corasick + LLM fallback)
//! - `webhook` — Webhook delivery with SSRF protection and circuit breakers
//! - [`common`] — Shared types, database pools, circuit breakers, error handling

pub mod analytics;
pub mod common;
pub mod email;
pub mod reply_handler;
pub mod webhook;

pub use analytics::AnalyticsProcessor;
pub use common::{ProcessorConfig, ProcessorError, ProcessorResult};
