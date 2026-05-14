//! # ops-service
//!
//! ApexMail operations service covering health checks, incident management,
//! SLO monitoring, status pages, IP warmup scheduling, trust scoring, and
//! SES monitoring (VDM, quota, deliverability metrics).

#![deny(unsafe_code)]
pub mod config;
pub mod health;
pub mod incidents;
pub mod routes;
pub mod ses_monitoring;
pub mod slo;
pub mod status;
pub mod trust;
pub mod types;
pub mod warmup;
