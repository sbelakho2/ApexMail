//! # TLS and HTTP/2 Fingerprinting
//!
//! This crate provides fingerprinting capabilities for identifying clients
//! based on their TLS and HTTP/2 behavior. This is useful for://!
//! - Bot detection (bots often have distinct fingerprints)
//! - Client identification (browsers have consistent fingerprints)
//! - Anomaly detection (unusual fingerprints may indicate attacks)
//!
//! ## JA4 TLS Fingerprinting
//!
//! JA4 is the successor to JA3, designed for TLS 1.3+ where many JA3
//! distinguishing features were removed. JA4 format://!
//! ```text
//! JA4 = JA4_a_JA4_b_JA4_c
//! JA4_a = protocol + SNI + cipher_count + extension_count + ALPN
//! JA4_b = truncated SHA256 of sorted cipher suites
//! JA4_c = truncated SHA256 of sorted extensions + signature algorithms
//! ```
//!
//! ## HTTP/2 Fingerprinting
//!
//! HTTP/2 fingerprinting uses SETTINGS frame values and pseudo-header
//! order to identify clients.

#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

mod database;
mod http2;
mod ja4;

pub use database::{
    ClientIdentity, CombinedFingerprint, FingerprintClassification, FingerprintDb,
    FingerprintDbConfig, SuspicionLevel,
};
pub use http2::{FrameType, Http2Fingerprint, Http2Preface, KnownHttp2Pattern};
pub use ja4::{ClientHello, Extension, Ja4Fingerprint, TlsVersion};
