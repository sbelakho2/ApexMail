//! High Availability service — health checks, failover, backup, replication,
//! multi-region routing, circuit breakers, and chaos engineering.

#![deny(unsafe_code)]
pub mod backup;
pub mod chaos;
pub mod circuit_breaker;
pub mod config;
pub mod failover;
/// SM10 F4: data-plane STONITH fence machinery — the pub helper api-server /
/// worker / mta consume to enforce the fence where writes happen. See the
/// module docs for the Redis key layout and integration contract.
pub mod fence;
pub mod health_check;
pub mod multi_region;
pub mod replication;
pub mod routes;
pub mod types;
