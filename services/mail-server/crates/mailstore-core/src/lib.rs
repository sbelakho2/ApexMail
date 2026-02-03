//! Mailstore Core
//!
//! Core library for email storage and retrieval.

mod storage;
mod models;
mod service;

pub use storage::*;
pub use models::*;
pub use service::*;
