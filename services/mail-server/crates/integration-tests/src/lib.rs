#![deny(unsafe_code)]
// Integration test crate — tests live in the `tests/` directory.
// This crate has no library code; it exists solely to host integration tests
// that exercise cross-service interactions via axum::test (tower oneshot).
