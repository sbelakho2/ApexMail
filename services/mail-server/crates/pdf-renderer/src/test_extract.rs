//! Test-only helpers: independent PDF text extraction and world fixtures.
//!
//! The extractor is deliberately a *different* implementation from the one
//! that produced the bytes (`pdf-extract`, a standalone PDF text extractor).
//! Tests use it to prove the delivered document's reading order and content,
//! which no assertion over the producer's own internals could establish.

use crate::world::TypstWorld;

/// Extract the reading-order text of a rendered PDF with an independent
/// extractor. Panics with the extractor's error when the bytes are not a
/// readable PDF — a render that cannot be extracted is a failure, not a skip.
pub fn extract_text(pdf: &[u8]) -> String {
    pdf_extract::extract_text_from_mem(pdf).expect("the rendered PDF must be extractable")
}

/// Build a world whose main source is the given Typst source (test-only:
/// exercises diagnostics and layout without touching the embedded templates).
pub fn world_with_source(source: &str) -> TypstWorld {
    let mut world =
        TypstWorld::new("invoice", "{}".to_string()).expect("base world must build");
    world.set_main_source_for_test(source);
    world
}
