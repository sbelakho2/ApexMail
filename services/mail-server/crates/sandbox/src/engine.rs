//! Sandbox engine — top-level orchestrator
//!
//! Coordinates file inspection, policy evaluation, and produces
//! a final `SandboxVerdict` for each attachment.

use crate::config::SandboxConfig;
use crate::file_inspector::{self, FileInspection};
use crate::policy::{self, PolicyDecision, PolicyResult};
use crate::SandboxError;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Final verdict for an attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxVerdict {
    /// Unique analysis ID
    pub analysis_id: String,
    /// SHA-256 of the file
    pub sha256: String,
    /// File size
    pub size: u64,
    /// Detected file type
    pub file_type: String,
    /// Original filename (if known)
    pub filename: Option<String>,
    /// Decision: allow, quarantine, reject
    pub decision: String,
    /// Risk score
    pub risk_score: f64,
    /// Detailed reasons
    pub reasons: Vec<String>,
    /// Individual findings
    pub findings: Vec<VerdictFinding>,
    /// Analysis timestamp (ISO 8601)
    pub timestamp: String,
}

/// A finding included in the verdict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictFinding {
    /// Finding ID
    pub id: String,
    /// Description
    pub description: String,
    /// Risk contribution
    pub risk: f64,
}

/// The sandbox engine
pub struct SandboxEngine {
    config: SandboxConfig,
}

impl SandboxEngine {
    /// Create engine with default config
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
        }
    }

    /// Create engine with custom config
    pub fn with_config(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Analyze a single attachment
    ///
    /// # Arguments
    /// * `data` - Raw file bytes
    /// * `filename` - Optional original filename
    ///
    /// # Returns
    /// A `SandboxVerdict` with the analysis results
    pub fn analyze(&self, data: &[u8], filename: Option<&str>) -> Result<SandboxVerdict, SandboxError> {
        // Pre-check: file size
        if data.len() as u64 > self.config.max_file_size {
            return Err(SandboxError::FileTooLarge {
                size: data.len() as u64,
                max: self.config.max_file_size,
            });
        }

        // Step 1: File inspection (static analysis)
        let inspection: FileInspection = file_inspector::inspect_file(data, filename);

        // Step 2: Policy evaluation
        let policy_result: PolicyResult = policy::evaluate_policy(&inspection, &self.config);

        // Step 3: Build verdict
        let verdict = SandboxVerdict {
            analysis_id: uuid::Uuid::new_v4().to_string(),
            sha256: inspection.sha256.clone(),
            size: inspection.size,
            file_type: inspection.file_type.to_string(),
            filename: filename.map(String::from),
            decision: policy_result.decision.to_string(),
            risk_score: policy_result.risk_score,
            reasons: policy_result.reasons,
            findings: inspection
                .findings
                .iter()
                .map(|f| VerdictFinding {
                    id: f.id.to_string(),
                    description: f.description.clone(),
                    risk: f.risk,
                })
                .collect(),
            timestamp: Utc::now().to_rfc3339(),
        };

        Ok(verdict)
    }

    /// Analyze multiple attachments in batch
    pub fn analyze_batch(
        &self,
        attachments: &[(&[u8], Option<&str>)],
    ) -> Vec<Result<SandboxVerdict, SandboxError>> {
        attachments
            .iter()
            .map(|(data, filename)| self.analyze(data, *filename))
            .collect()
    }

    /// Check if a verdict resulted in rejection
    pub fn is_rejected(verdict: &SandboxVerdict) -> bool {
        verdict.decision == PolicyDecision::Reject.to_string()
    }

    /// Check if any verdict in a batch resulted in rejection
    pub fn any_rejected(verdicts: &[Result<SandboxVerdict, SandboxError>]) -> bool {
        verdicts.iter().any(|v| {
            matches!(v, Ok(v) if Self::is_rejected(v))
                || matches!(v, Err(_))
        })
    }
}

impl Default for SandboxEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_clean_text() {
        let engine = SandboxEngine::new();
        let data = b"Hello, this is a clean text file.";
        let verdict = engine.analyze(data, Some("readme.txt")).expect("analysis failed");
        assert_eq!(verdict.decision, "ALLOW");
        assert!(verdict.risk_score < 5.0);
    }

    #[test]
    fn test_analyze_executable() {
        let engine = SandboxEngine::new();
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let verdict = engine.analyze(&data, Some("malware.exe")).expect("analysis failed");
        assert_eq!(verdict.decision, "REJECT");
        assert!(verdict.risk_score >= 10.0);
    }

    #[test]
    fn test_file_too_large() {
        let config = SandboxConfig {
            max_file_size: 100,
            ..Default::default()
        };
        let engine = SandboxEngine::with_config(config);
        let data = vec![0u8; 200];
        let result = engine.analyze(&data, Some("big.bin"));
        assert!(matches!(result, Err(SandboxError::FileTooLarge { .. })));
    }

    #[test]
    fn test_batch_analysis() {
        let engine = SandboxEngine::new();
        let clean = b"Just some text" as &[u8];
        let exe = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let attachments: Vec<(&[u8], Option<&str>)> = vec![
            (clean, Some("readme.txt")),
            (&exe, Some("update.exe")),
        ];
        let results = engine.analyze_batch(&attachments);
        assert_eq!(results.len(), 2);
        assert!(SandboxEngine::any_rejected(&results));
    }

    #[test]
    fn test_verdict_serializable() {
        let engine = SandboxEngine::new();
        let data = b"Hello world";
        let verdict = engine.analyze(data, Some("test.txt")).expect("analysis failed");
        let json = serde_json::to_string(&verdict).expect("serialize failed");
        assert!(json.contains("analysis_id"));
        assert!(json.contains("sha256"));
    }

    #[test]
    fn test_double_extension_attack() {
        let engine = SandboxEngine::new();
        let data = b"Not really a PDF";
        let verdict = engine.analyze(data, Some("invoice.pdf.exe")).expect("analysis failed");
        assert_eq!(verdict.decision, "REJECT");
        assert!(verdict.findings.iter().any(|f| f.id == "DOUBLE_EXTENSION"));
    }
}
