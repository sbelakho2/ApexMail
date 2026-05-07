//! Shared billing logic used by both `billing-service` and `api-server`.
//!
//! This crate provides a single source of truth for:
//!
//! - **VAT rates** — EU member states and their standard VAT rates
//!   ([`vat_rates`])
//! - **Proration** — plan-change proration calculations ([`proration`])
//! - **Audit** — audit log ID generation and hashing ([`audit`])
//! - **CSV** — CSV value sanitisation ([`csv`])

pub mod audit;
pub mod csv;
pub mod proration;
pub mod vat_rates;
