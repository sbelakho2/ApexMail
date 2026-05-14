#![allow(clippy::doc_lazy_continuation)]
//! # Sandbox — Secure Attachment Detonation
//!
//! Provides a sandboxed execution environment for analyzing email attachments,
//! inspecting file contents, and detecting malicious payloads without executing
//! arbitrary code on the host system.
//!
//! ## Architecture
//!
//! The sandbox operates at multiple levels://!
//! 1. **Static analysis** — File magic detection, extension validation, hash computation
//! 2. **Content inspection** — Archive enumeration, embedded macro detection, OLE parsing
//! 3. **Policy engine** — Configurable allowlists/blocklists, size limits, nesting depth limits
//! 4. **Verdict generation** — Risk scoring and actionable classification
//!
//! On Linux, this module can additionally leverage://! - **Namespaces** (mount, PID, network, user) for filesystem isolation
//! - **cgroups v2** for memory/CPU limits on analysis processes
//! - **seccomp-BPF** for syscall filtering
//!
//! These OS-level features are behind the `linux-sandbox` feature flag.
//!
//! ## Non-Linux Platforms
//!
//! On non-Linux (macOS, Windows), full process isolation is unavailable.
//! The sandbox still provides static analysis, content inspection, and policy enforcement,
//! which catch the vast majority of malicious attachments without process execution.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

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
