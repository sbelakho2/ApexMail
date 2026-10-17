//! Mailstore Core
//!
//! Core library for email storage and retrieval.

#![deny(unsafe_code)]
mod encryption;
/// Mail journal (migration 264): the shared gate, transactional write and
/// tenant-scoped retrieval used by the worker, mailstore and api-server.
pub mod journal;
mod models;
mod service;
mod storage;
#[cfg(test)]
mod test_db;

pub use encryption::*;
pub use models::*;
pub use service::*;
pub use storage::*;
