//! Mailstore Core
//!
//! Core library for email storage and retrieval.

#![deny(unsafe_code)]
mod encryption;
mod models;
mod service;
mod storage;
#[cfg(test)]
mod test_db;

pub use encryption::*;
pub use models::*;
pub use service::*;
pub use storage::*;
