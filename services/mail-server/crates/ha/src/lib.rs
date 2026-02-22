//! High Availability service — health checks, failover, backup, replication,
//! multi-region routing, circuit breakers, and chaos engineering.

pub mod config;
pub mod types;
pub mod health_check;
pub mod failover;
pub mod backup;
pub mod replication;
pub mod multi_region;
pub mod circuit_breaker;
pub mod chaos;
pub mod routes;
