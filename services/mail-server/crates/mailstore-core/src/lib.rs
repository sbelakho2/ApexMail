//! Mailstore Core
//!
//! Core library for email storage and retrieval.

mod models;
mod service;
mod storage;

pub use models::*;
pub use service::*;
pub use storage::*;
