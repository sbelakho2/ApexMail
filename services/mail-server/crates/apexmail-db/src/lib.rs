//! ApexMail database layer — connection pool, repositories, transactions.
//!
//! Provides type-safe PostgreSQL access for all ApexMail services.

#![deny(unsafe_code)]
pub mod migrations;
pub mod pool;
pub mod repos;
pub mod transaction;
pub mod types;

pub use pool::{create_pool, create_pool_pair, DatabasePool, PoolPair, PoolType, WriteTracker};
pub use types::*;
