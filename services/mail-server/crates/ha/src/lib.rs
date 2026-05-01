//! High Availability service — health checks, failover, backup, replication,
//! multi-region routing, circuit breakers, and chaos engineering.

pub mod backup;
pub mod chaos;
pub mod circuit_breaker;
pub mod config;
pub mod failover;
pub mod health_check;
pub mod multi_region;
pub mod replication;
pub mod routes;
pub mod types;
