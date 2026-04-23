pub mod marketing;
pub mod data;
pub mod icons;
pub mod primitives;
pub mod routing;
pub mod shell;
pub mod tokens;
pub mod leptos_views;
pub mod ssr;
pub mod axum_router;
pub mod pixel_parity;

#[cfg(test)]
mod migration_tests;

pub const FOUNDATION_MANIFEST_JSON: &str = include_str!("../../../../../docs/development/ui-rust-foundation-manifest.json");
pub const GLOBALS_CSS: &str = include_str!("../../../../../apps/testing/fixtures/rust-ui/assets/globals.css");
