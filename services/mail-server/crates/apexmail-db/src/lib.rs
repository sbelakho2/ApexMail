//! ApexMail database layer — connection pool, repositories, transactions.
//!
//! Provides type-safe PostgreSQL access for all ApexMail services.

pub mod pool;
pub mod repos;
pub mod types;
pub mod transaction;
pub mod migrations;

pub use pool::{create_pool, DatabasePool};
pub use types::*;
