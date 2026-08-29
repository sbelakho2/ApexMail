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
use std::time::Duration;
use tracing::{error, warn};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DynamicDecision {
    /// Dynamic analysis observed no blocking behavior.
    #[default]
    #[serde(rename = "Allow")]
    Allow,
    /// Dynamic analysis recommends escalating to quarantine.
    #[serde(rename = "Flag")]
    Flag,
    /// Dynamic analysis recommends outright rejection.
    #[serde(rename = "Reject")]
    Reject,
}

/// Shared, bounded Tokio runtime used to run dynamic analyzers.
///
/// Previously every attachment analysis spawned a dedicated OS thread *and*
/// built a fresh Tokio runtime — one thread + one runtime leaked per
/// analysis for stuck scanners. All analyses now share this single runtime
/// with a small bounded blocking pool; analyzer implementations are expected
/// to enforce their own I/O timeouts (the ClamAV analyzer sets socket
/// read/write timeouts) so blocked scans cannot hold pool slots forever.
fn shared_analyzer_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .thread_name("sandbox-analyzer")
            .build()
            .expect("failed to build shared sandbox analyzer runtime")
    })
}

/// Instrumentation for the shared analyzer blocking pool.
///
/// `spawn_blocking` closures that never return (an analyzer without an
/// internal I/O timeout, a wedged scanner socket) hold one of the 8
/// blocking threads forever. The caller's `tokio::time::timeout` abandons
/// the *await*, not the pool slot — so eight stuck analyzers wedge the
/// entire pool: every later analysis queues forever, times out, and fails
/// closed (`any_rejected()` returns true for `Err` verdicts) with no
/// recovery.
///
/// Every dispatched task registers its start time here and removes it when
/// the blocking closure actually returns (RAII [`SlotGuard`]). Slots that
/// stay in flight for more than 2× the configured analyzer timeout are
/// reported once each with a loud ERROR and counted in a process-wide
/// metric.
///
/// ## Operator note
///
/// If [`analyzer_wedge_events`] is non-zero (and especially if
/// [`analyzer_slots_in_flight`] stays pinned at the pool bound of 8), the
/// shared analyzer pool is wedged by analyzers that do not enforce their
/// own timeouts. Analysis requests will fail closed until the **process
/// is restarted** — wedged blocking threads cannot be reclaimed from
/// inside the process. After restart, fix or remove the analyzer that
/// lacks an internal I/O timeout (every `DynamicAnalyzer` must bound its
/// own blocking work).
#[derive(Default)]
struct AnalyzerSlotTracker {
    in_flight: std::sync::Mutex<std::collections::HashMap<u64, SlotState>>,
    next_id: std::sync::atomic::AtomicU64,
    wedge_events: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Copy)]
struct SlotState {
    started: std::time::Instant,
    wedge_reported: bool,
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            started: std::time::Instant::now(),
            wedge_reported: false,
        }
    }
}

static ANALYZER_SLOTS: std::sync::OnceLock<AnalyzerSlotTracker> = std::sync::OnceLock::new();

fn analyzer_slots() -> &'static AnalyzerSlotTracker {
    ANALYZER_SLOTS.get_or_init(AnalyzerSlotTracker::default)
}

/// Metric: analyzer blocking-pool slots currently in flight.
pub fn analyzer_slots_in_flight() -> usize {
    analyzer_slots()
        .in_flight
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len()
}

/// Metric: analyzer wedge detections since process start. Non-zero means
/// at least one analyzer task outlived 2× its configured timeout — see the
/// operator note on [`AnalyzerSlotTracker`].
pub fn analyzer_wedge_events() -> u64 {
    analyzer_slots()
        .wedge_events
        .load(std::sync::atomic::Ordering::Relaxed)
}

/// RAII removal of a slot registration: dropped when the blocking closure
/// truly returns, which is the only correct moment to forget the slot.
struct SlotGuard {
    id: u64,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let tracker = analyzer_slots();
        tracker
            .in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
    }
}

impl AnalyzerSlotTracker {
    fn register(&self) -> SlotGuard {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                id,
                SlotState {
                    started: std::time::Instant::now(),
                    wedge_reported: false,
                },
            );
        SlotGuard { id }
    }
}

/// Report (once per slot) in-flight slots older than 2× the analyzer
/// timeout. Called on every dispatch and after every analyzer wait.
fn check_for_wedged_slots(timeout: Duration) {
    let wedge_after = timeout.saturating_mul(2);
    let tracker = analyzer_slots();
    let mut wedged = Vec::new();
    {
        let mut slots = tracker.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        for (id, state) in slots.iter_mut() {
            if !state.wedge_reported && state.started.elapsed() > wedge_after {
                state.wedge_reported = true;
                wedged.push((*id, state.started.elapsed()));
            }
        }
    }
    for (id, age) in wedged {
        tracker
            .wedge_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        error!(
            slot = id,
            in_flight_secs = age.as_secs_f64(),
            timeout_secs = timeout.as_secs(),
            in_flight_now = analyzer_slots_in_flight(),
            pool_bound = 8,
            "SANDBOX ANALYZER POOL WEDGE: blocking task outlived 2x its timeout and is holding a pool slot. \
             If in_flight reaches the pool bound all analyses will fail closed until the process is restarted. \
             Every DynamicAnalyzer must enforce its own I/O timeout."
        );
    }
}

/// Optional dynamic analyzer (detonation / behavioral emulation)./// **No concrete implementation is provided by this crate.** This trait is an
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
    pub fn with_dynamic_analyzer(
        config: SandboxConfig,
        analyzer: Arc<dyn DynamicAnalyzer>,
    ) -> Self {
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
    pub fn analyze(
        &self,
        data: &[u8],
        filename: Option<&str>,
    ) -> Result<SandboxVerdict, SandboxError> {
        // Pre-check:file size
        if data.len() as u64 > self.config.max_file_size {
            return Err(SandboxError::FileTooLarge {
                size: data.len() as u64,
                max: self.config.max_file_size,
            });
        }

        // Step 1:File inspection (static analysis)
        let mut inspection: FileInspection = file_inspector::inspect_file(data, filename);

        // ---- Apply configurable encrypted-archive risk (O-15.2) -----------
        // The built-in `inspect_file` hard-codes 7.0 for ARCHIVE_ENCRYPTED.
        // If the operator has configured a different value, adjust here so
        // legitimate encrypted archives (legal docs, payroll, …) can be
        // tuned per trust-domain.
        let default_encrypted_risk = 7.0;
        if (self.config.encrypted_archive_risk - default_encrypted_risk).abs() > 0.001 {
            let delta = self.config.encrypted_archive_risk - default_encrypted_risk;
            let mut encrypted_count: f64 = 0.0;
            for finding in &mut inspection.findings {
                if finding.id == "ARCHIVE_ENCRYPTED" {
                    finding.risk = self.config.encrypted_archive_risk;
                    encrypted_count += 1.0;
                }
            }
            // Total risk was already incremented by 7.0 for each encrypted
            // finding; apply the delta so the effective contribution becomes
            // `encrypted_archive_risk` per finding.
            inspection.risk_score = (inspection.risk_score + delta * encrypted_count).max(0.0);
        }

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
            if let Some(dynamic_finding) = self.run_dynamic_analyzer(data, filename, analyzer)? {
                Self::apply_dynamic_finding(&mut verdict, dynamic_finding);
            }
        }

        Ok(verdict)
    }

    fn run_dynamic_analyzer(
        &self,
        data: &[u8],
        filename: Option<&str>,
        analyzer: &Arc<dyn DynamicAnalyzer>,
    ) -> Result<Option<DynamicAnalysisFinding>, SandboxError> {
        let timeout_duration = Duration::from_secs(self.config.analysis_timeout_secs);
        let analyzer = Arc::clone(analyzer);
        let data = data.to_vec();
        let filename = filename.map(str::to_string);

        // Run on the shared, bounded blocking pool instead of spawning a
        // fresh OS thread + Tokio runtime per attachment (which leaked one
        // thread and one runtime per analysis). The pool size bounds the
        // number of concurrently-stuck analyzer tasks; each analyzer is
        // expected to enforce its own I/O timeouts (e.g. the ClamAV socket
        // read/write timeout) so stalled scans release their pool slot.
        let runtime = shared_analyzer_runtime();
        // Register the slot BEFORE dispatch so a wedge (a task that never
        // returns, holding one of the 8 blocking threads) is observable.
        let slot = analyzer_slots().register();
        check_for_wedged_slots(timeout_duration);
        let task = runtime.spawn_blocking(move || {
            // RAII: the entry is removed when the blocking task actually
            // finishes — even if the caller already abandoned it after a
            // timeout, which is exactly the wedge case we need to see.
            let _guard = slot;
            analyzer.analyze(&data, filename.as_deref())
        });

        let joined = runtime.block_on(async {
            match tokio::time::timeout(timeout_duration, task).await {
                Ok(Ok(finding)) => Ok(finding),
                Ok(Err(error)) => Err(format!("dynamic analyzer task failed: {error}")),
                Err(_) => Err(format!(
                    "dynamic analyzer timed out after {} seconds",
                    timeout_duration.as_secs()
                )),
            }
        });

        // Re-check after the wait: a task that outlived its own timeout is
        // a wedge candidate.
        check_for_wedged_slots(timeout_duration);

        match joined {
            Ok(finding) => Ok(finding),
            Err(message) => {
                warn!(error = %message, "dynamic analyzer failed");
                Err(SandboxError::AnalysisError(message))
            }
        }
    }

    fn apply_dynamic_finding(
        verdict: &mut SandboxVerdict,
        dynamic_finding: DynamicAnalysisFinding,
    ) {
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
        verdicts
            .iter()
            .any(|v| matches!(v, Ok(v) if Self::is_rejected(v)) || v.is_err())
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
    ) -> (
        Result<SandboxVerdict, crate::SandboxError>,
        mail_common::security::SecurityEvent,
    ) {
        let result = self.analyze(data, filename);
        let correlation =
            correlation.unwrap_or_else(mail_common::security::CorrelationContext::generated);

        let (action, severity, risk_score, description) = match &result {
            Ok(v) if v.decision == "REJECT" => (
                mail_common::security::SecurityAction::Reject,
                mail_common::security::SecuritySeverity::Critical,
                v.risk_score.min(10.0),
                format!(
                    "Sandbox REJECT file={} risk={:.1}",
                    v.file_type, v.risk_score
                ),
            ),
            Ok(v) if v.decision == "QUARANTINE" => (
                mail_common::security::SecurityAction::Quarantine,
                mail_common::security::SecuritySeverity::High,
                v.risk_score.min(10.0),
                format!(
                    "Sandbox QUARANTINE file={} risk={:.1}",
                    v.file_type, v.risk_score
                ),
            ),
            Ok(v) => (
                mail_common::security::SecurityAction::Allow,
                mail_common::security::SecuritySeverity::Info,
                v.risk_score.min(10.0),
                format!(
                    "Sandbox ALLOW file={} risk={:.1}",
                    v.file_type, v.risk_score
                ),
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
            event
                .metadata
                .insert("composite_alert".to_string(), "true".to_string());
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
    struct MockDynamicSlow;

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

    impl DynamicAnalyzer for MockDynamicSlow {
        fn analyze(&self, _data: &[u8], _filename: Option<&str>) -> Option<DynamicAnalysisFinding> {
            std::thread::sleep(std::time::Duration::from_millis(1_500));
            Some(DynamicAnalysisFinding {
                id: "DYNAMIC_SLOW".into(),
                description: "Slow dynamic analyzer completed after timeout".into(),
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
        let attachments: Vec<(&[u8], Option<&str>)> =
            vec![(clean, Some("readme.txt")), (&exe, Some("update.exe"))];
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

    #[test]
    fn test_dynamic_analysis_timeout_fails_closed() {
        let config = SandboxConfig {
            analysis_timeout_secs: 1,
            ..Default::default()
        };
        let engine = SandboxEngine::with_dynamic_analyzer(config, Arc::new(MockDynamicSlow));

        let result = engine.analyze(b"hello", Some("readme.txt"));

        assert!(matches!(
            result,
            Err(SandboxError::AnalysisError(message)) if message.contains("timed out")
        ));
    }

    struct MockDynamicStuck;

    impl DynamicAnalyzer for MockDynamicStuck {
        fn analyze(&self, _data: &[u8], _filename: Option<&str>) -> Option<DynamicAnalysisFinding> {
            // No internal timeout: outlives the engine timeout by far.
            std::thread::sleep(std::time::Duration::from_secs(5));
            None
        }
    }

    #[test]
    fn test_analyzer_wedge_detected_and_slot_eventually_released() {
        // Pool-wedge instrumentation: an analyzer without an internal
        // timeout holds one of the 8 blocking threads past the engine
        // timeout. The slot must stay observable as in-flight, a later
        // dispatch must record a wedge event (loud ERROR + metric), and
        // when the stuck task finally finishes its RAII guard must release
        // the slot.
        let config = SandboxConfig {
            analysis_timeout_secs: 1,
            ..Default::default()
        };
        let stuck = SandboxEngine::with_dynamic_analyzer(config, Arc::new(MockDynamicStuck));
        let wedges_before = analyzer_wedge_events();

        // First call: times out (fail closed) while the task keeps running.
        let result = stuck.analyze(b"hello", Some("stuck.bin"));
        assert!(result.is_err(), "stuck analyzer must fail closed");
        assert!(
            analyzer_slots_in_flight() >= 1,
            "abandoned task must remain observable as in-flight"
        );

        // Let the slot age past 2x the timeout, then dispatch a fast
        // analysis — the wedge check must fire. The 2.6s wait gives the
        // slot a >=0.6s margin over the 2x(1s) threshold: under a fully
        // parallel test run the first dispatch's own scheduling delay eats
        // into a 1.5s wait and the check races the threshold.
        std::thread::sleep(std::time::Duration::from_millis(2_600));
        // The wedge sweep runs on the DYNAMIC-analyzer dispatch path — the
        // probe must be a fast DYNAMIC analyzer, not the static-only
        // with_config engine (whose analyze never reaches the check).
        struct MockDynamicFast;
        impl DynamicAnalyzer for MockDynamicFast {
            fn analyze(
                &self,
                _data: &[u8],
                _filename: Option<&str>,
            ) -> Option<DynamicAnalysisFinding> {
                None
            }
        }
        // Same 1s timeout as the stuck engine: the wedge threshold is 2x the
        // DISPATCHING engine's timeout, and the probe must judge the stuck
        // slot against the same clock that abandoned it.
        let mut fast_config = SandboxConfig::default();
        fast_config.analysis_timeout_secs = 1;
        let fast = SandboxEngine::with_dynamic_analyzer(fast_config, Arc::new(MockDynamicFast));
        let fast_result = fast.analyze(b"hello", Some("ok.txt"));
        assert!(fast_result.is_ok());
        assert!(
            analyzer_wedge_events() > wedges_before,
            "slot older than 2x timeout must be counted as a wedge event"
        );

        // Once the stuck task truly finishes, its guard releases the slot.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while analyzer_slots_in_flight() > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(
            analyzer_slots_in_flight(),
            0,
            "slot must be released when the blocking task finally returns"
        );
    }

    #[test]
    fn test_repeated_stuck_analyzes_share_bounded_pool() {
        // Regression:previously each analysis spawned its own thread +
        // runtime; a stuck analyzer leaked both. With the shared bounded
        // pool, repeated analyses must each still hit their timeout (i.e.
        // the engine never deadlocks or queues forever behind stuck tasks).
        let config = SandboxConfig {
            analysis_timeout_secs: 1,
            ..Default::default()
        };
        let engine = SandboxEngine::with_dynamic_analyzer(config, Arc::new(MockDynamicSlow));

        let start = std::time::Instant::now();
        for _ in 0..3 {
            let result = engine.analyze(b"hello", Some("readme.txt"));
            assert!(
                matches!(
                    result,
                    Err(SandboxError::AnalysisError(ref message)) if message.contains("timed out")
                ),
                "each stuck analysis must fail with a timeout"
            );
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "3 timeout-bounded analyses must not run unbounded: {:?}",
            elapsed
        );
    }
}
