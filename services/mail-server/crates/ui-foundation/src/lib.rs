#![deny(unsafe_code)]
pub mod axum_router;
pub mod csrf;
pub mod data;
pub mod icons;
pub mod leptos_views;
pub mod marketing;
pub mod pixel_parity;
pub mod primitives;
pub mod routing;
pub mod shell;
pub mod ssr;
pub mod tokens;

#[cfg(test)]
mod migration_tests;

pub const FOUNDATION_MANIFEST_JSON: &str =
    include_str!("../../../../../docs/development/ui-rust-foundation-manifest.json");
pub const GLOBALS_CSS: &str = include_str!("../assets/globals.css");
