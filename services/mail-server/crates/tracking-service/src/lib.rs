//! Library surface of the tracking service.
//!
//! C (worker/processes token unification): the codec module is exposed so
//! other ApexMail components (notably the worker-processors email tracker
//! that ENCODES tracking tokens) can share the exact same implementation
//! and stay byte-format compatible with this service's DECODE path.

pub mod bot;
pub mod codec;
pub mod config;
pub mod processor;
pub mod routes;
pub mod state;
pub mod templates;
