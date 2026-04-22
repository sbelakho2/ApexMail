//! # Observability Service
//!
//! ApexMail observability platform providing://! - **Prometheus metrics** collection (counters, histograms, gauges)
//! - **Distributed tracing** with span collection and search
//! - **OpenTelemetry OTLP export** for distributed tracing backends
//! - **Log aggregation** with structured query and error-rate analysis
//! - **Alerting** with rule evaluation, firing, acknowledgement
//! - **SLO monitoring** with error-budget tracking
//! - **Health-check dashboards** exposed via Axum HTTP routes

pub mod alerting;
pub mod config;
pub mod log_aggregator;
pub mod metrics_collector;
pub mod otlp_exporter;
pub mod routes;
pub mod slo;
pub mod trace_collector;
pub mod types;
