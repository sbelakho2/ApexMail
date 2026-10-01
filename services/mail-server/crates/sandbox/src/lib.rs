#![allow(clippy::doc_lazy_continuation)]
//! # Sandbox — Attachment Content Inspection
//!
//! Provides bounded, in-process inspection of email attachments:
//! file-type detection, content analysis, and policy evaluation — without
//! ever executing the inspected content.
//!
//! ## Architecture
//!
//! The sandbox operates at multiple levels://!
//! 1. **Static analysis** — File magic detection, extension validation, hash computation
//! 2. **Content inspection** — Archive enumeration, embedded macro detection, OLE parsing
//! 3. **Bounded archive extraction** — ZIP containers are recursed into up to
//!    `max_nesting_depth` levels under `max_archive_entries` and
//!    `max_total_extracted_size` budgets; every extracted entry is
//!    re-inspected on its DECOMPRESSED content ([`archive`])
//! 4. **Policy engine** — Configurable allowlists/blocklists, size limits, nesting depth limits
//! 5. **Verdict generation** — Risk scoring and actionable classification
//!
//! ## What this is NOT (read before relying on it)
//!
//! This module performs **static analysis only**. Despite claims in
//! historical revisions of these docs, it does NOT use Linux namespaces,
//! cgroups v2, seccomp-BPF, or any other OS-level isolation primitive,
//! there is no `linux-sandbox` feature flag, and no process is ever
//! spawned: there is no detonation. Resource usage is bounded by explicit
//! budgets (file size, extraction bytes/entries, analysis wall-clock), not
//! by an OS sandbox. The optional [`dynamic_analyzers`] hooks (YARA-style
//! signatures, ClamAV) are also plain in-process scanners.
//!
//! ## Platform notes
//!
//! The static inspection and archive extraction run identically on every
//! platform. The ClamAV dynamic analyzer requires a Unix domain socket and
//! fails closed (explicit unsupported verdict) on non-Unix targets.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod archive;
pub mod config;
pub mod dynamic_analyzers;
pub mod engine;
pub mod file_inspector;
pub mod policy;

use thiserror::Error;

/// Sandbox errors
#[derive(Debug, Error)]
pub enum SandboxError {
    /// I/O error during file operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File exceeds maximum allowed size
    #[error("File too large: {size} bytes (max: {max})")]
    FileTooLarge {
        /// Actual size
        size: u64,
        /// Maximum allowed
        max: u64,
    },

    /// Nesting depth exceeded (zip bomb detection)
    #[error("Nesting depth exceeded: {depth} (max: {max})")]
    NestingDepthExceeded {
        /// Actual depth
        depth: u32,
        /// Maximum allowed
        max: u32,
    },

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Internal analysis error
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}
