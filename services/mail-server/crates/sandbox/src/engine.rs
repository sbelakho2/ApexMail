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
use std::sync::Arc;

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
/// Decision:allow, quarantine, reject
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

/// Dynamic-analysis engine result.
#[derive(Debug, Clone)]
pub struct DynamicAnalysisFinding {
/// Dynamic finding identifier.
    pub id: String,
/// Human-readable behavior description.
    pub description: String,
/// Risk contribution from dynamic analysis.
    pub risk: f64,
/// Decision requested by the dynamic analyzer.
    pub decision: DynamicDecision,
}

/// Decision returned by dynamic analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicDecision {
/// Dynamic analysis observed no blocking behavior.
    Allow,
/// Dynamic analysis recommends escalating to quarantine.
    Flag,
/// Dynamic analysis recommends outright rejection.
    Reject,
}

/// Optional dynamic analyzer (detonation / behavioral emulation).
/// **No concrete implementation is provided by this crate.** This trait is an
/// integration hook for callers that have access to a sandboxing backend such
/// as a micro-VM detonation chamber, YARA/ClamAV scan integration, or
/// behavioral emulation engine. To use it:/// 1. Implement `DynamicAnalyzer` for your backend.
/// 2. Pass it to [`SandboxEngine::with_dynamic_analyzer`].
/// 3. If `analyze` returns `Some(finding)`, the finding's risk is added to the
/// static verdict and the decision is escalated according to
/// [`DynamicDecision`].
/// **Known limitation — recursive archives:** The current static inspector
/// does not recurse into nested ZIP/RAR archives or decompress PDF object
/// streams. A `DynamicAnalyzer` implementation can compensate by unpacking
/// and re-scanning inner payloads.
/// **Known limitation — image-based payloads:** Steganographic or image-rendered
/// content (e.g., phishing screenshots) is not inspected. An OCR-equipped
/// dynamic analyzer can fill this gap.
pub trait DynamicAnalyzer: Send + Sync {
/// Run dynamic analysis on the attachment and optionally return a finding.
    fn analyze(&self, data: &[u8], filename: Option<&str>) -> Option<DynamicAnalysisFinding>;
}

/// The sandbox engine.
/// Orchestrates static file inspection via [`file_inspector`] and policy
/// evaluation via [`policy`], then optionally merges results from a
/// [`DynamicAnalyzer`] implementation to produce a final [`SandboxVerdict`].
pub struct SandboxEngine {
    config: SandboxConfig,
    dynamic_analyzer: Option<Arc<dyn DynamicAnalyzer>>,
}

impl SandboxEngine {
/// Create engine with default config
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
            dynamic_analyzer: None,
        }
    }

/// Create engine with custom config
    pub fn with_config(config: SandboxConfig) -> Self {
        Self {
            config,
            dynamic_analyzer: None,
        }
    }

/// Create engine with optional dynamic analyzer.
    pub fn with_dynamic_analyzer(config: SandboxConfig, analyzer: Arc<dyn DynamicAnalyzer>) -> Self {
        Self {
            config,
            dynamic_analyzer: Some(analyzer),
        }
    }

/// Analyze a single attachment
/// # Arguments
/// * `data` - Raw file bytes
/// * `filename` - Optional original filename
/// # Returns
/// A `SandboxVerdict` with the analysis results
    pub fn analyze(&self, data: &[u8], filename: Option<&str>) -> Result<SandboxVerdict, SandboxError> {
// Pre-check:file size
        if data.len() as u64 > self.config.max_file_size {
            return Err(SandboxError::FileTooLarge {
                size: data.len() as u64,
                max: self.config.max_file_size,
            });
        }

// Step 1:File inspection (static analysis)
        let inspection: FileInspection = file_inspector::inspect_file(data, filename);

// Step 2:Policy evaluation
        let policy_result: PolicyResult = policy::evaluate_policy(&inspection, &self.config);

// Step 3:Build verdict
        let mut verdict = SandboxVerdict {
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

        if let Some(analyzer) = &self.dynamic_analyzer {
            if let Some(dynamic_finding) = analyzer.analyze(data, filename) {
                verdict.risk_score += dynamic_finding.risk;
                verdict.reasons.push(dynamic_finding.description.clone());
                verdict.findings.push(VerdictFinding {
                    id: dynamic_finding.id,
                    description: dynamic_finding.description,
                    risk: dynamic_finding.risk,
                });

                match dynamic_finding.decision {
                    DynamicDecision::Allow => {}
                    DynamicDecision::Flag => {
                        if verdict.decision == PolicyDecision::Allow.to_string() {
                            verdict.decision = PolicyDecision::Quarantine.to_string();
                        }
                    }
                    DynamicDecision::Reject => {
                        verdict.decision = PolicyDecision::Reject.to_string();
                    }
                }
            }
        }

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
                || v.is_err()
        })
    }
}

#[cfg(feature = "events")]
impl SandboxEngine {
/// Analyze an attachment and also produce a normalized security event.
/// Requires the `events` feature flag (which enables the `mail-common` dep).
    pub fn analyze_with_event(
        &self,
        data: &[u8],
        filename: Option<&str>,
        correlation: Option<mail_common::security::CorrelationContext>,
    ) -> (Result<SandboxVerdict, crate::SandboxError>, mail_common::security::SecurityEvent) {
        let result = self.analyze(data, filename);
        let correlation = correlation.unwrap_or_else(
            mail_common::security::CorrelationContext::generated,
        );

        let (action, severity, risk_score, description) = match &result {
            Ok(v) if v.decision == "REJECT" => (
                mail_common::security::SecurityAction::Reject,
                mail_common::security::SecuritySeverity::Critical,
                v.risk_score.min(10.0),
                format!("Sandbox REJECT file={} risk={:.1}", v.file_type, v.risk_score),
            ),
            Ok(v) if v.decision == "QUARANTINE" => (
                mail_common::security::SecurityAction::Quarantine,
                mail_common::security::SecuritySeverity::High,
                v.risk_score.min(10.0),
                format!("Sandbox QUARANTINE file={} risk={:.1}", v.file_type, v.risk_score),
            ),
            Ok(v) => (
                mail_common::security::SecurityAction::Allow,
                mail_common::security::SecuritySeverity::Info,
                v.risk_score.min(10.0),
                format!("Sandbox ALLOW file={} risk={:.1}", v.file_type, v.risk_score),
            ),
            Err(e) => (
                mail_common::security::SecurityAction::Block,
                mail_common::security::SecuritySeverity::High,
                10.0,
                format!("Sandbox error: {}", e),
            ),
        };

        let mut event = mail_common::security::SecurityEvent::new(
            mail_common::security::SecuritySystem::Sandbox,
            action,
            severity,
            risk_score,
            description,
            correlation,
        );

        if let Some(alert) = mail_common::security::ingest_security_event(event.clone()) {
            event.metadata.insert("composite_alert".to_string(), "true".to_string());
            event.metadata.insert(
                "composite_score".to_string(),
                format!("{:.2}", alert.composite_score),
            );
            event.metadata.insert(
                "composite_action".to_string(),
                format!("{:?}", alert.recommended_action),
            );
        }

        (result, event)
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

    struct MockDynamicReject;

    impl DynamicAnalyzer for MockDynamicReject {
        fn analyze(&self, _data: &[u8], _filename: Option<&str>) -> Option<DynamicAnalysisFinding> {
            Some(DynamicAnalysisFinding {
                id: "DYNAMIC_BEHAVIOR".into(),
                description: "Process-spawn behavior observed in detonation".into(),
                risk: 8.0,
                decision: DynamicDecision::Reject,
            })
        }
    }

    #[test]
    fn test_analyze_clean_text() {
        let engine = SandboxEngine::new();
        let data = b"Hello, this is a clean text file.";
        let verdict = engine.analyze(data, Some("readme.txt"));
        assert!(verdict.is_ok(), "analysis should succeed");
        if let Ok(verdict) = verdict {
            assert_eq!(verdict.decision, "ALLOW");
            assert!(verdict.risk_score < 5.0);
        }
    }

    #[test]
    fn test_analyze_executable() {
        let engine = SandboxEngine::new();
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let verdict = engine.analyze(&data, Some("malware.exe"));
        assert!(verdict.is_ok(), "analysis should succeed");
        if let Ok(verdict) = verdict {
            assert_eq!(verdict.decision, "REJECT");
            assert!(verdict.risk_score >= 10.0);
        }
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
        let verdict = engine.analyze(data, Some("test.txt"));
        assert!(verdict.is_ok(), "analysis should succeed");
        if let Ok(verdict) = verdict {
            let json = serde_json::to_string(&verdict);
            assert!(json.is_ok(), "serialize should succeed");
            if let Ok(json) = json {
                assert!(json.contains("analysis_id"));
                assert!(json.contains("sha256"));
            }
        }
    }

    #[test]
    fn test_double_extension_attack() {
        let engine = SandboxEngine::new();
        let data = b"Not really a PDF";
        let verdict = engine.analyze(data, Some("invoice.pdf.exe"));
        assert!(verdict.is_ok(), "analysis should succeed");
        if let Ok(verdict) = verdict {
            assert_eq!(verdict.decision, "REJECT");
            assert!(verdict.findings.iter().any(|f| f.id == "DOUBLE_EXTENSION"));
        }
    }

    #[test]
    fn test_dynamic_analysis_escalation() {
        let engine = SandboxEngine::with_dynamic_analyzer(
            SandboxConfig::default(),
            Arc::new(MockDynamicReject),
        );
        let verdict = engine.analyze(b"hello", Some("readme.txt"));
        assert!(verdict.is_ok(), "analysis should succeed");
        if let Ok(verdict) = verdict {
            assert_eq!(verdict.decision, "REJECT");
            assert!(verdict.findings.iter().any(|f| f.id == "DYNAMIC_BEHAVIOR"));
        }
    }
}
