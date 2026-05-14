//! ApexMail MTA – Mail Transfer Agent
//!
//! Provides inbound SMTP reception, bounce processing, feedback‑loop handling,
//! and comprehensive email authentication (SPF, DKIM, DMARC, ARC, BIMI, DANE, MTA‑STS).

#![deny(unsafe_code)]
pub mod auth;
pub mod config;
pub mod gmail_annotations;
pub mod postmaster;
pub mod servers;

pub use config::MtaConfig;
