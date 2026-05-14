//! # Bounce Analytics
//!
//! A dedicated crate for email bounce analytics: aggregation, pattern detection,
//! trend analysis, domain reputation scoring, and burst detection.
//!
//! ## Architecture
//!
//! This crate processes bounce events from the `bounce_events` table (populated by
//! the MTA bounce server) and produces:
//!
//! - **Daily aggregations** stored in `bounce_analytics_daily`
//! - **Domain reputation** stored in `bounce_domain_reputation`
//! - **Burst alerts** stored in `bounce_bursts`
//!
//! A [`BounceAnalyticsReport`](types::BounceAnalyticsReport) can be queried on
//! demand to produce a full snapshot of bounce health for a tenant.

#![deny(unsafe_code)]
pub mod aggregator;
pub mod config;
pub mod types;
