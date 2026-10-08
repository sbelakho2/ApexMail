//! ApexMail PDF Renderer — Typst-powered document generation.
//!
//! This crate provides://! - A Typst virtual filesystem (`TypstWorld`) for template resolution
//! - A compiler that turns `.typ` templates + JSON data → PDF bytes
//! - Axum HTTP routes for on-demand rendering
//!
//! Templates are embedded at compile time from `src/templates/`.

#![deny(unsafe_code)]
pub mod auth;
pub mod compiler;
pub mod routes;
pub mod world;

#[cfg(test)]
mod test_extract;

pub use auth::ServiceAuth;
pub use compiler::render_pdf;
pub use routes::pdf_router;
