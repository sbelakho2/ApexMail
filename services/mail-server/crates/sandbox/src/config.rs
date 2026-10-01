//! Sandbox configuration

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Maximum file size in bytes (default:25 MB)
    pub max_file_size: u64,

    /// Maximum nesting depth for archives (zip bomb protection).
    /// Enforced by [`crate::archive::extract_and_inspect`]: ZIP containers
    /// deeper than this are not recursed into and the refusal is reported
    /// as an explicit `ARCHIVE_NESTING_EXCEEDED` finding.
    pub max_nesting_depth: u32,

    /// Maximum total extracted size from archives (decompression bomb
    /// protection). Enforced by [`crate::archive::extract_and_inspect`]:
    /// cumulative decompressed bytes across the whole sweep; exceeding it
    /// stops extraction and reports `ARCHIVE_BOMB`.
    pub max_total_extracted_size: u64,

    /// Maximum number of files inside an archive. Enforced by
    /// [`crate::archive::extract_and_inspect`] across the whole sweep;
    /// exceeding it stops extraction and reports `ARCHIVE_ENTRY_CAP`.
    pub max_archive_entries: u32,

    /// Dangerous file extensions that trigger elevated analysis
    pub dangerous_extensions: HashSet<String>,

    /// Blocked file extensions (always reject)
    pub blocked_extensions: HashSet<String>,

    /// Blocked MIME types (always reject). The static engine maps the
    /// magic-byte-detected file type (and the `.hta` extension) onto its
    /// canonical MIME and enforces this list during policy evaluation.
    pub blocked_mime_types: HashSet<String>,

    /// Score threshold for flagging as suspicious (default:5.0)
    pub suspicious_threshold: f64,

    /// Score threshold for rejecting (default:10.0)
    pub reject_threshold: f64,

    /// Whether to analyze embedded OLE/macro content. When `false`,
    /// macro-indicator findings are suppressed on the container AND on
    /// every extracted archive entry (see [`SandboxConfig::reports_finding`]).
    pub analyze_macros: bool,

    /// Whether to analyze embedded URLs / remote links in documents. When
    /// `false`, the corresponding findings are suppressed (see
    /// [`SandboxConfig::reports_finding`]).
    pub analyze_embedded_urls: bool,

    /// Analysis timeout in seconds
    pub analysis_timeout_secs: u64,

    /// Risk contribution for encrypted / password‑protected archives (O-15.2).
    ///
    /// Legitimate use‑cases (e.g. legal document exchange, encrypted payroll)
    /// may require sending password‑protected archives.  Lower this value to
    /// reduce false positives for trusted senders / domains.  Default: `7.0`.
    pub encrypted_archive_risk: f64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_file_size: 25 * 1024 * 1024, // 25 MB
            max_nesting_depth: 3,
            max_total_extracted_size: 100 * 1024 * 1024, // 100 MB
            max_archive_entries: 1000,
            dangerous_extensions: [
                "exe", "dll", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf",
                "wsh", "ps1", "ps2", "psc1", "msi", "msp", "mst", "cpl", "hta", "inf", "ins",
                "isp", "reg", "rgs", "sct", "shb", "shs", "lnk", "jar", "class", "docm", "dotm",
                "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm", "mht",
                "mhtml",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            blocked_extensions: [
                "exe", "dll", "scr", "bat", "cmd", "com", "pif", "hta", "cpl", "msi", "ps1", "vbs",
                "vbe", "wsf",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            blocked_mime_types: [
                "application/x-msdownload",
                "application/x-msdos-program",
                "application/x-dosexec",
                "application/hta",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            suspicious_threshold: 5.0,
            reject_threshold: 10.0,
            analyze_macros: true,
            analyze_embedded_urls: true,
            analysis_timeout_secs: 30,
            encrypted_archive_risk: 7.0,
        }
    }
}

impl SandboxConfig {
    /// Whether a static-analysis finding with `id` should be reported,
    /// honoring the [`SandboxConfig::analyze_macros`] and
    /// [`SandboxConfig::analyze_embedded_urls`] switches. Applied
    /// uniformly to the outer container and to every extracted archive
    /// entry so the knobs govern both consistently.
    pub(crate) fn reports_finding(&self, id: &str) -> bool {
        if !self.analyze_macros && matches!(id, "OOXML_MACRO" | "OOXML_VBA_BIN" | "OLE2_VBA_MACROS")
        {
            return false;
        }
        if !self.analyze_embedded_urls && matches!(id, "OOXML_EXTERNAL_OLE" | "PDF_URI") {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dangerous_extensions_include_macro_and_mhtml_formats() {
        let config = SandboxConfig::default();

        for extension in ["xlsb", "xlam", "mht", "mhtml"] {
            assert!(
                config.dangerous_extensions.contains(extension),
                "expected .{extension} to be treated as dangerous"
            );
        }
    }
}
