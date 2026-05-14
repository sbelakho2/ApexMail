//! Sandbox configuration

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Maximum file size in bytes (default:25 MB)
    pub max_file_size: u64,

    /// Maximum nesting depth for archives (zip bomb protection)
    pub max_nesting_depth: u32,

    /// Maximum total extracted size from archives (decompression bomb protection)
    pub max_total_extracted_size: u64,

    /// Maximum number of files inside an archive
    pub max_archive_entries: u32,

    /// Dangerous file extensions that trigger elevated analysis
    pub dangerous_extensions: HashSet<String>,

    /// Blocked file extensions (always reject)
    pub blocked_extensions: HashSet<String>,

    /// Blocked MIME types (always reject)
    pub blocked_mime_types: HashSet<String>,

    /// Score threshold for flagging as suspicious (default:5.0)
    pub suspicious_threshold: f64,

    /// Score threshold for rejecting (default:10.0)
    pub reject_threshold: f64,

    /// Whether to analyze embedded OLE/macro content
    pub analyze_macros: bool,

    /// Whether to analyze embedded URLs in documents
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
