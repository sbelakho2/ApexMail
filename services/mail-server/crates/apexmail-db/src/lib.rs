//! ApexMail database layer — connection pool, repositories, transactions.
//!
//! Provides type-safe PostgreSQL access for all ApexMail services.

pub mod migrations;
pub mod pool;
pub mod repos;
pub mod transaction;
pub mod types;

pub use pool::{create_pool, DatabasePool};
pub use types::*;
