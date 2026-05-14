//! ApexMail Developer Experience service.
//!
//! Handles API versioning, SDK management, CLI tools, webhook testing,
//! OpenAPI documentation, developer onboarding, and API key management.

#![deny(unsafe_code)]
pub mod config;
pub mod onboarding;
pub mod openapi;
pub mod routes;
pub mod sdk_manager;
pub mod types;
pub mod versioning;
pub mod webhook_tester;
