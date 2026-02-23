//! # ops-service
//!
//! ApexMail operations service covering health checks, incident management,
//! SLO monitoring, status pages, IP warmup scheduling, and trust scoring.

pub mod config;
pub mod health;
pub mod incidents;
pub mod routes;
pub mod slo;
pub mod status;
pub mod trust;
pub mod types;
pub mod warmup;
