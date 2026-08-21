//! Attachment security policy engine
//!
//! Configurable rules that determine whether an attachment is allowed,
//! quarantined, or rejected based on its inspection results.

use crate::config::SandboxConfig;
use crate::file_inspector::{FileInspection, FileType};

/// Policy decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Attachment is allowed
    Allow,
    /// Attachment is quarantined for review
    Quarantine,
    /// Attachment is rejected
    Reject,
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyDecision::Allow => write!(f, "ALLOW"),
            PolicyDecision::Quarantine => write!(f, "QUARANTINE"),
            PolicyDecision::Reject => write!(f, "REJECT"),
        }
    }
}

/// Policy evaluation result
#[derive(Debug, Clone)]
pub struct PolicyResult {
    /// Decision
    pub decision: PolicyDecision,
    /// Reasons for the decision
    pub reasons: Vec<String>,
    /// The accumulated risk score
    pub risk_score: f64,
}

/// Evaluate an attachment against the security policy
pub fn evaluate_policy(inspection: &FileInspection, config: &SandboxConfig) -> PolicyResult {
    let mut reasons = Vec::with_capacity(6);
    let mut risk_score = inspection.risk_score;
    let mut force_reject = false;

    // 1. Blocked extension (blocked_extensions ∪ dangerous_extensions —
    //    the "dangerous" set is the operator's elevated-analysis list and
    //    previously had no effect at all; both sets now block).
    if let Some(ref ext) = inspection.extension {
        if config.blocked_extensions.contains(ext) {
            reasons.push(format!("Blocked extension: .{}", ext));
            force_reject = true;
        } else if config.dangerous_extensions.contains(ext) {
            reasons.push(format!("Dangerous extension: .{}", ext));
            force_reject = true;
        }
    }

    // 2. File size limit
    if inspection.size > config.max_file_size {
        reasons.push(format!(
            "File too large: {} bytes (max: {})",
            inspection.size, config.max_file_size
        ));
        force_reject = true;
    }

    // 3. Executable file types always rejected
    match inspection.file_type {
        FileType::PeExe | FileType::Elf | FileType::MachO => {
            reasons.push(format!("Executable file type: {}", inspection.file_type));
            force_reject = true;
        }
        _ => {}
    }

    // 4. Extension mismatch is suspicious
    if inspection.extension_mismatch {
        reasons.push("File extension does not match detected content type".into());
        risk_score += 2.0;
    }

    // 5. Decide based on score thresholds
    let decision = if force_reject {
        PolicyDecision::Reject
    } else if risk_score >= config.reject_threshold {
        reasons.push(format!(
            "Risk score {:.1} exceeds reject threshold {:.1}",
            risk_score, config.reject_threshold
        ));
        PolicyDecision::Reject
    } else if risk_score >= config.suspicious_threshold {
        reasons.push(format!(
            "Risk score {:.1} exceeds suspicious threshold {:.1}",
            risk_score, config.suspicious_threshold
        ));
        PolicyDecision::Quarantine
    } else {
        PolicyDecision::Allow
    };

    PolicyResult {
        decision,
        reasons,
        risk_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_inspector;

    #[test]
    fn test_allow_clean_pdf() {
        let data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let inspection = file_inspector::inspect_file(data, Some("report.pdf"));
        let config = SandboxConfig::default();
        let result = evaluate_policy(&inspection, &config);
        assert_eq!(result.decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_reject_executable() {
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let inspection = file_inspector::inspect_file(&data, Some("payload.exe"));
        let config = SandboxConfig::default();
        let result = evaluate_policy(&inspection, &config);
        assert_eq!(result.decision, PolicyDecision::Reject);
    }

    #[test]
    fn test_dangerous_extension_blocks() {
        // `.jar` is in dangerous_extensions but NOT in blocked_extensions —
        // previously the dangerous set was dead configuration and the file
        // would have been allowed. The union must now reject.
        let data = b"plain text wearing a dangerous extension";
        let inspection = file_inspector::inspect_file(data, Some("applet.jar"));
        let config = SandboxConfig::default();
        assert!(
            config.dangerous_extensions.contains("jar"),
            "test premise:jar must be in the default dangerous set"
        );
        assert!(!config.blocked_extensions.contains("jar"));
        let result = evaluate_policy(&inspection, &config);
        assert_eq!(
            result.decision,
            PolicyDecision::Reject,
            "dangerous extensions must be enforced: {:?}",
            result.reasons
        );
        assert!(result.reasons.iter().any(|r| r.contains("jar")));
    }

    #[test]
    fn test_quarantine_suspicious() {
        // PDF with JavaScript and OpenAction
        let data = b"%PDF-1.4\n<< /Type /Action /S /JavaScript /JS (x) >>\n/OpenAction";
        let inspection = file_inspector::inspect_file(data, Some("invoice.pdf"));
        let config = SandboxConfig::default();
        let result = evaluate_policy(&inspection, &config);
        assert!(
            result.decision == PolicyDecision::Quarantine
                || result.decision == PolicyDecision::Reject,
            "Expected quarantine or reject, got {:?}",
            result.decision
        );
    }

    #[test]
    fn test_reject_oversized() {
        // Create inspection with oversized file
        let inspection = FileInspection {
            file_type: FileType::Zip,
            sha256: "abc123".into(),
            size: 100 * 1024 * 1024, // 100 MB
            extension: Some("zip".into()),
            extension_mismatch: false,
            findings: vec![],
            risk_score: 0.0,
        };
        let config = SandboxConfig::default(); // 25 MB max
        let result = evaluate_policy(&inspection, &config);
        assert_eq!(result.decision, PolicyDecision::Reject);
    }

    #[test]
    fn test_reject_blocked_extension() {
        let data = b"Hello world";
        let inspection = file_inspector::inspect_file(data, Some("script.vbs"));
        let config = SandboxConfig::default();
        let result = evaluate_policy(&inspection, &config);
        assert_eq!(result.decision, PolicyDecision::Reject);
    }
}
