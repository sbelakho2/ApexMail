//! ApexMail AI Intelligence Suite.
//!
//! The service combines deterministic helpers with an explicitly configured,
//! authenticated model runtime. Model inference, experimentation, and training
//! are opt-in operations with data validation, promotion controls, and safety
//! gates; they are not silently replaced with placeholder responses.

#![deny(unsafe_code)]
pub mod analytics;
pub mod assistant;
pub mod bandits;
pub mod config;
pub mod content;
pub mod defense;
pub mod domain_dns;
pub mod email_agent;
pub mod governor;
pub mod inference;
pub mod pipeline;
pub mod routes;
pub mod sto;
pub mod tools;
pub mod training;
pub mod types;
pub mod verifier;
