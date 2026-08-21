//! Spam filter engine — orchestrates all analyzers
//!
//! Combines Bayesian classification, content scoring, header analysis,
//! and URL analysis into a single composite spam verdict.

use crate::bayesian::{BayesianClassifier, BayesianModel, TrainingError};
use crate::config::SpamConfig;
use crate::content_scorer::{self, ContentFinding, ContentScore};
use crate::header_analyzer::{self, EmailHeaders, HeaderScore};
use crate::url_analyzer::{self, UrlScore};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Composite spam verdict
#[derive(Debug, Clone)]
pub struct SpamVerdict {
    /// Final composite score (higher = more likely spam)
    pub score: f64,
    /// Classification decision
    pub classification: SpamClass,
    /// Bayesian probability (0.0 = ham, 1.0 = spam)
    pub bayesian_probability: f64,
    /// Header analysis result
    pub header_score: HeaderScore,
    /// Content analysis result
    pub content_score: ContentScore,
    /// URL analysis result
    pub url_score: UrlScore,
}

/// Spam classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamClass {
    /// Legitimate email
    Ham,
    /// Probable spam (flag/quarantine)
    Spam,
    /// Definite spam (reject)
    Reject,
}

impl std::fmt::Display for SpamClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpamClass::Ham => write!(f, "HAM"),
            SpamClass::Spam => write!(f, "SPAM"),
            SpamClass::Reject => write!(f, "REJECT"),
        }
    }
}

/// Label for a reviewed training sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainingLabel {
    /// Sample is confirmed spam.
    Spam,
    /// Sample is confirmed ham (legitimate).
    Ham,
}

/// Pending training sample awaiting review.
#[derive(Debug, Clone)]
pub struct PendingTrainingSample {
    /// Unique queue identifier for the sample.
    pub id: String,
    /// Reviewer label to apply if approved.
    pub label: TrainingLabel,
    /// Raw training text payload.
    pub text: String,
    /// Identity of the user/system that submitted the sample.
    pub submitted_by: String,
    /// Submission timestamp.
    pub submitted_at: DateTime<Utc>,
}

/// Snapshot of Bayesian model for rollback.
#[derive(Debug, Clone)]
pub struct BayesianSnapshot {
    /// Unique snapshot identifier.
    pub id: String,
    /// Human-readable snapshot label.
    pub label: String,
    /// Snapshot creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Serialized model state captured at snapshot time.
    pub model: BayesianModel,
}

/// Drift signal from recent classification probabilities.
#[derive(Debug, Clone)]
pub struct DriftStatus {
    /// Number of samples included in the rolling window.
    pub sample_count: usize,
    /// Baseline mean established for drift comparison.
    pub baseline_mean: Option<f64>,
    /// Current rolling mean from recent probabilities.
    pub rolling_mean: f64,
    /// Absolute delta between rolling mean and baseline.
    pub delta: f64,
    /// Whether the configured drift threshold is exceeded.
    pub alert: bool,
}

/// Per-class drift status showing ham→spam and spam→ham boundary shifts.
#[derive(Debug, Clone)]
pub struct PerClassDriftStatus {
    /// Overall drift status (global).
    pub overall: DriftStatus,
    /// Rolling mean for messages classified as spam.
    pub spam_rolling_mean: f64,
    /// Number of spam samples in the rolling window.
    pub spam_sample_count: usize,
    /// Rolling mean for messages classified as ham.
    pub ham_rolling_mean: f64,
    /// Number of ham samples in the rolling window.
    pub ham_sample_count: usize,
    /// Direction of drift.
    pub direction: DriftDirection,
}

/// Direction of model drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftDirection {
    /// Model is drifting towards classifying more as spam.
    TowardsSpam,
    /// Model is drifting towards classifying more as ham.
    TowardsHam,
    /// Stable — no significant directional drift.
    Stable,
}

/// The spam filter engine
pub struct SpamEngine {
    config: SpamConfig,
    bayesian: BayesianClassifier,
    /// Per-tenant Bayesian classifiers (key:tenant_id), LRU-bounded
    tenant_classifiers: Arc<RwLock<HashMap<String, BayesianClassifier>>>,
    /// Insertion-order ring for tenant-classifier LRU eviction
    tenant_order: Arc<RwLock<VecDeque<String>>>,
    approved_reviewers: Arc<RwLock<HashSet<String>>>,
    pending_samples: Arc<RwLock<VecDeque<PendingTrainingSample>>>,
    model_snapshots: Arc<RwLock<HashMap<String, BayesianSnapshot>>>,
    /// Insertion-order ring for snapshot LRU eviction
    snapshot_order: Arc<RwLock<VecDeque<String>>>,
    recent_probabilities: Arc<RwLock<VecDeque<f64>>>,
    baseline_probability: Arc<RwLock<Option<f64>>>,
    /// Per-class drift tracking:separate rolling windows for spam and ham
    recent_spam_probabilities: Arc<RwLock<VecDeque<f64>>>,
    recent_ham_probabilities: Arc<RwLock<VecDeque<f64>>>,
}

/// Maximum number of per-tenant classifiers retained in memory (LRU).
const MAX_TENANT_CLASSIFIERS: usize = 1000;
/// Maximum number of model snapshots retained in memory (LRU).
const MAX_MODEL_SNAPSHOTS: usize = 50;

impl SpamEngine {
    /// Create a new spam engine with default config
    pub fn new() -> Self {
        Self {
            config: SpamConfig::default(),
            bayesian: BayesianClassifier::new(BayesianModel::default()),
            tenant_classifiers: Arc::new(RwLock::new(HashMap::new())),
            tenant_order: Arc::new(RwLock::new(VecDeque::new())),
            approved_reviewers: Arc::new(RwLock::new(HashSet::new())),
            pending_samples: Arc::new(RwLock::new(VecDeque::new())),
            model_snapshots: Arc::new(RwLock::new(HashMap::new())),
            snapshot_order: Arc::new(RwLock::new(VecDeque::new())),
            recent_probabilities: Arc::new(RwLock::new(VecDeque::new())),
            baseline_probability: Arc::new(RwLock::new(None)),
            recent_spam_probabilities: Arc::new(RwLock::new(VecDeque::new())),
            recent_ham_probabilities: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Create with custom config
    pub fn with_config(config: SpamConfig) -> Self {
        Self {
            config,
            bayesian: BayesianClassifier::new(BayesianModel::default()),
            tenant_classifiers: Arc::new(RwLock::new(HashMap::new())),
            tenant_order: Arc::new(RwLock::new(VecDeque::new())),
            approved_reviewers: Arc::new(RwLock::new(HashSet::new())),
            pending_samples: Arc::new(RwLock::new(VecDeque::new())),
            model_snapshots: Arc::new(RwLock::new(HashMap::new())),
            snapshot_order: Arc::new(RwLock::new(VecDeque::new())),
            recent_probabilities: Arc::new(RwLock::new(VecDeque::new())),
            baseline_probability: Arc::new(RwLock::new(None)),
            recent_spam_probabilities: Arc::new(RwLock::new(VecDeque::new())),
            recent_ham_probabilities: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Get a reference to the Bayesian classifier for training
    pub fn bayesian(&self) -> &BayesianClassifier {
        &self.bayesian
    }

    /// Analyze an email and produce a composite verdict
    pub fn analyze(
        &self,
        body: &str,
        headers: &[(String, String)],
        auth_results: Option<&str>,
    ) -> SpamVerdict {
        // 1. Bayesian classification with cold-start protection
        let bayesian_prob = if self.config.enable_bayesian {
            let raw_prob = self.bayesian.classify(body);
            // Cold-start:if model has insufficient training data, treat as neutral.
            // Uses the cheap O(1) accessor — a full export_model() here would
            // deep-clone the entire vocabulary on every email.
            if self.bayesian.total_samples() < self.config.min_training_samples as u64 {
                0.5 // Neutral — don't let an under-trained model influence scoring
            } else {
                raw_prob
            }
        } else {
            0.5
        };

        // 2. Header analysis
        let email_headers = EmailHeaders {
            headers,
            auth_results,
        };
        let header_result = if self.config.enable_header_analysis {
            header_analyzer::analyze_headers(&email_headers)
        } else {
            HeaderScore {
                score: 0.0,
                findings: Vec::new(),
            }
        };

        // 3. Content scoring (including custom phrase blocklists — shared
        // with analyze_for_tenant so both entry points score identically)
        let content_result = self.score_content_with_blocklists(body);

        // 4. URL analysis
        let url_result = if self.config.enable_url_analysis {
            url_analyzer::analyze_urls_with_shorteners(body, Some(&self.config.url_shorteners))
        } else {
            UrlScore {
                score: 0.0,
                findings: Vec::new(),
                url_count: 0,
            }
        };

        // 5. DMARC policy enforcement (shared path)
        let dmarc_penalty = self.check_dmarc_policy(auth_results);

        // 6. Composite scoring + classification (shared path)
        let (composite, classification) =
            self.composite_score(bayesian_prob, &header_result, &content_result, &url_result, dmarc_penalty);

        self.record_probability(bayesian_prob);

        SpamVerdict {
            score: composite,
            classification,
            bayesian_probability: bayesian_prob,
            header_score: header_result,
            content_score: content_result,
            url_score: url_result,
        }
    }

    /// Content scoring including the tenant-configured custom phrase
    /// blocklists. Shared by `analyze` and `analyze_for_tenant` so the two
    /// entry points cannot drift apart again.
    fn score_content_with_blocklists(&self, body: &str) -> ContentScore {
        if !self.config.enable_content_scoring {
            return ContentScore {
                score: 0.0,
                findings: Vec::new(),
            };
        }
        let mut base_score = content_scorer::score_content(body);
        let lower_body = body.to_lowercase();
        for phrase_list in &self.config.custom_phrase_blocklists {
            for phrase in &phrase_list.phrases {
                if lower_body.contains(&phrase.to_lowercase()) {
                    base_score.score += 1.5 * phrase_list.weight;
                    base_score.findings.push(ContentFinding {
                        id: "CUSTOM_PHRASE",
                        description: format!(
                            "Custom phrase [{}]: \"{}\"",
                            phrase_list.category, phrase
                        ),
                        penalty: 1.5 * phrase_list.weight,
                    });
                }
            }
        }
        base_score
    }

    /// Shared composite scoring + classification. Keeping the formula in one
    /// place guarantees `analyze` and `analyze_for_tenant` stay equivalent.
    fn composite_score(
        &self,
        probability: f64,
        header_result: &HeaderScore,
        content_result: &ContentScore,
        url_result: &UrlScore,
        dmarc_penalty: f64,
    ) -> (f64, SpamClass) {
        let composite = (probability * 10.0 * self.config.bayesian_weight)
            + (header_result.score * self.config.header_weight)
            + (content_result.score * self.config.content_weight)
            + (url_result.score * self.config.url_weight)
            + dmarc_penalty;

        let classification = if composite >= self.config.reject_threshold {
            SpamClass::Reject
        } else if composite >= self.config.spam_threshold {
            SpamClass::Spam
        } else {
            SpamClass::Ham
        };

        (composite, classification)
    }

    /// Train the Bayesian classifier with a spam sample.
    ///
    /// The input is validated (entropy check, token count limit) and
    /// rate-limited before being ingested into the model. Returns an
    /// error if the sample fails validation or the rate limit is exceeded.
    pub fn train_spam(&self, text: &str) -> Result<(), TrainingError> {
        self.bayesian.learn_spam_validated(text)
    }

    /// Train the Bayesian classifier with a ham sample.
    ///
    /// The input is validated (entropy check, token count limit) and
    /// rate-limited before being ingested into the model. Returns an
    /// error if the sample fails validation or the rate limit is exceeded.
    pub fn train_ham(&self, text: &str) -> Result<(), TrainingError> {
        self.bayesian.learn_ham_validated(text)
    }

    /// Add an approved reviewer identity.
    pub fn add_reviewer(&self, reviewer: &str) {
        self.approved_reviewers.write().insert(reviewer.to_string());
    }

    /// Queue a training sample for explicit review/approval.
    pub fn submit_training_sample(
        &self,
        label: TrainingLabel,
        text: &str,
        submitted_by: &str,
    ) -> Option<String> {
        let mut pending = self.pending_samples.write();
        if pending.len() >= self.config.max_pending_training_samples {
            return None;
        }

        let id = format!("train-{}", uuid::Uuid::new_v4());
        pending.push_back(PendingTrainingSample {
            id: id.clone(),
            label,
            text: text.to_string(),
            submitted_by: submitted_by.to_string(),
            submitted_at: Utc::now(),
        });
        Some(id)
    }

    /// List queued training samples.
    pub fn pending_training_samples(&self) -> Vec<PendingTrainingSample> {
        self.pending_samples.read().iter().cloned().collect()
    }

    /// Approve and apply a queued training sample.
    pub fn approve_training_sample(&self, sample_id: &str, reviewer: &str) -> bool {
        if self.config.enable_guarded_training && !self.approved_reviewers.read().contains(reviewer)
        {
            return false;
        }

        let mut pending = self.pending_samples.write();
        let index = pending.iter().position(|s| s.id == sample_id);
        let Some(index) = index else {
            return false;
        };

        let Some(sample) = pending.remove(index) else {
            return false;
        };
        // Route through the validated (entropy/token-count checked,
        // rate-limited) learning path. A rejected sample is discarded — it
        // must never bypass validation by using the legacy unvalidated API.
        let trained = match sample.label {
            TrainingLabel::Spam => self.bayesian.learn_spam_validated(&sample.text),
            TrainingLabel::Ham => self.bayesian.learn_ham_validated(&sample.text),
        };
        if let Err(e) = trained {
            tracing::warn!(
                sample_id = %sample_id,
                reviewer = %reviewer,
                error = ?e,
                "Approved training sample failed validation — discarded"
            );
        }
        true
    }

    /// Reject and discard a queued training sample.
    pub fn reject_training_sample(&self, sample_id: &str) -> bool {
        let mut pending = self.pending_samples.write();
        let index = pending.iter().position(|s| s.id == sample_id);
        let Some(index) = index else {
            return false;
        };
        pending.remove(index);
        true
    }

    /// Persist an in-memory model snapshot for rollback.
    /// Snapshots are LRU-bounded (MAX_MODEL_SNAPSHOTS) — the oldest snapshot
    /// is evicted once the cap is reached so long-running processes cannot
    /// accumulate unbounded model copies.
    pub fn create_model_snapshot(&self, label: &str) -> String {
        let snapshot = BayesianSnapshot {
            id: format!("snapshot-{}", uuid::Uuid::new_v4()),
            label: label.to_string(),
            created_at: Utc::now(),
            model: self.bayesian.export_model(),
        };
        let id = snapshot.id.clone();
        let mut snapshots = self.model_snapshots.write();
        let mut order = self.snapshot_order.write();
        snapshots.insert(id.clone(), snapshot);
        order.push_back(id.clone());
        while snapshots.len() > MAX_MODEL_SNAPSHOTS {
            if let Some(oldest) = order.pop_front() {
                snapshots.remove(&oldest);
            } else {
                break;
            }
        }
        id
    }

    /// Restore a previously saved model snapshot.
    pub fn rollback_to_snapshot(&self, snapshot_id: &str) -> bool {
        let model = self
            .model_snapshots
            .read()
            .get(snapshot_id)
            .map(|s| s.model.clone());
        let Some(model) = model else {
            return false;
        };
        self.bayesian.replace_model(model);
        true
    }

    /// Inspect current drift status.
    pub fn drift_status(&self) -> DriftStatus {
        let probs = self.recent_probabilities.read();
        let sample_count = probs.len();
        let rolling_mean = if probs.is_empty() {
            0.5
        } else {
            probs.iter().sum::<f64>() / probs.len() as f64
        };
        let baseline = *self.baseline_probability.read();
        let delta = baseline.map(|b| (rolling_mean - b).abs()).unwrap_or(0.0);
        let alert = sample_count >= self.config.min_samples_for_drift
            && baseline.is_some()
            && delta >= self.config.drift_alert_delta;

        DriftStatus {
            sample_count,
            baseline_mean: baseline,
            rolling_mean,
            delta,
            alert,
        }
    }

    /// Enhanced per-class drift status showing ham→spam and spam→ham boundary shifts.
    pub fn per_class_drift_status(&self) -> PerClassDriftStatus {
        let spam_probs = self.recent_spam_probabilities.read();
        let ham_probs = self.recent_ham_probabilities.read();

        let spam_mean = if spam_probs.is_empty() {
            0.5
        } else {
            spam_probs.iter().sum::<f64>() / spam_probs.len() as f64
        };

        let ham_mean = if ham_probs.is_empty() {
            0.5
        } else {
            ham_probs.iter().sum::<f64>() / ham_probs.len() as f64
        };

        let overall = self.drift_status();

        PerClassDriftStatus {
            overall,
            spam_rolling_mean: spam_mean,
            spam_sample_count: spam_probs.len(),
            ham_rolling_mean: ham_mean,
            ham_sample_count: ham_probs.len(),
            direction: if spam_mean > ham_mean + 0.2 {
                DriftDirection::TowardsSpam
            } else if ham_mean > spam_mean + 0.2 {
                DriftDirection::TowardsHam
            } else {
                DriftDirection::Stable
            },
        }
    }

    /// Analyze an email with tenant-scoped Bayesian prior adjustment.
    /// The global model provides the baseline, and the tenant classifier
    /// provides an additional offset so that one tenant's training does not
    /// shift another tenant's spam threshold.
    pub fn analyze_for_tenant(
        &self,
        body: &str,
        headers: &[(String, String)],
        auth_results: Option<&str>,
        tenant_id: &str,
    ) -> SpamVerdict {
        let global_prob = if self.config.enable_bayesian {
            self.bayesian.classify(body)
        } else {
            0.5
        };

        // Get or create per-tenant classifier for namespace isolation
        let tenant_prob = {
            let classifiers = self.tenant_classifiers.read();
            if let Some(tc) = classifiers.get(tenant_id) {
                tc.classify(body)
            } else {
                // No tenant-specific model yet — fall back to global
                global_prob
            }
        };

        // Blend:60% global + 40% tenant-specific for stability
        let blended_prob = global_prob * 0.6 + tenant_prob * 0.4;

        // 2. Header analysis
        let email_headers = EmailHeaders {
            headers,
            auth_results,
        };
        let header_result = if self.config.enable_header_analysis {
            header_analyzer::analyze_headers(&email_headers)
        } else {
            HeaderScore {
                score: 0.0,
                findings: Vec::new(),
            }
        };

        // 3. Content scoring (including custom phrase blocklists — shared
        // scoring path with `analyze`)
        let content_result = self.score_content_with_blocklists(body);

        // 4. URL analysis
        let url_result = if self.config.enable_url_analysis {
            url_analyzer::analyze_urls_with_shorteners(body, Some(&self.config.url_shorteners))
        } else {
            UrlScore {
                score: 0.0,
                findings: Vec::new(),
                url_count: 0,
            }
        };

        // 5. DMARC policy enforcement check
        let dmarc_penalty = self.check_dmarc_policy(auth_results);

        // 6. Composite scoring + classification (shared path)
        let (composite, classification) = self.composite_score(
            blended_prob,
            &header_result,
            &content_result,
            &url_result,
            dmarc_penalty,
        );

        self.record_probability(blended_prob);
        self.record_per_class_probability(blended_prob, &classification);

        SpamVerdict {
            score: composite,
            classification,
            bayesian_probability: blended_prob,
            header_score: header_result,
            content_score: content_result,
            url_score: url_result,
        }
    }

    /// Train the per-tenant Bayesian classifier with a spam sample.
    /// The classifier map is LRU-bounded (MAX_TENANT_CLASSIFIERS) so a
    /// multi-tenant deployment cannot grow it without bound.
    pub fn train_tenant_spam(&self, tenant_id: &str, text: &str) {
        let mut classifiers = self.tenant_classifiers.write();
        let mut order = self.tenant_order.write();
        let classifier = classifiers
            .entry(tenant_id.to_string())
            .or_insert_with(|| BayesianClassifier::new(BayesianModel::default()));
        classifier.learn_spam(text);
        order.push_back(tenant_id.to_string());
        while classifiers.len() > MAX_TENANT_CLASSIFIERS {
            if let Some(oldest) = order.pop_front() {
                classifiers.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Train the per-tenant Bayesian classifier with a ham sample
    /// (LRU-bounded, see [`Self::train_tenant_spam`]).
    pub fn train_tenant_ham(&self, tenant_id: &str, text: &str) {
        let mut classifiers = self.tenant_classifiers.write();
        let mut order = self.tenant_order.write();
        let classifier = classifiers
            .entry(tenant_id.to_string())
            .or_insert_with(|| BayesianClassifier::new(BayesianModel::default()));
        classifier.learn_ham(text);
        order.push_back(tenant_id.to_string());
        while classifiers.len() > MAX_TENANT_CLASSIFIERS {
            if let Some(oldest) = order.pop_front() {
                classifiers.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Check DMARC policy enforcement from auth_results header.
    /// If DMARC fails and the policy is p=reject or p=quarantine, apply a penalty
    /// to the spam score. This ensures that even if the MTA did not enforce DMARC,
    /// the spam filter adds its own correction.
    fn check_dmarc_policy(&self, auth_results: Option<&str>) -> f64 {
        let Some(results) = auth_results else {
            return 0.0;
        };
        let lower = results.to_lowercase();
        // dmarc=none is informational only:many legitimate senders publish no
        // DMARC record. It is NOT a failure — treat it as a weak signal
        // (0.5), consistent with header_analyzer's scoring.
        if lower.contains("dmarc=none") {
            return 0.5;
        }
        if lower.contains("dmarc=fail") {
            // DMARC explicitly failed — apply the full penalty (the actual
            // DNS p= policy would need an async lookup, so we apply a
            // conservative penalty that acknowledges the failure without
            // blocking outright).
            return 2.5;
        }
        0.0
    }

    fn record_per_class_probability(&self, probability: f64, class: &SpamClass) {
        let window_size = self.config.min_samples_for_drift.max(10);
        match class {
            SpamClass::Spam | SpamClass::Reject => {
                let mut w = self.recent_spam_probabilities.write();
                w.push_back(probability);
                if w.len() > window_size {
                    w.pop_front();
                }
            }
            SpamClass::Ham => {
                let mut w = self.recent_ham_probabilities.write();
                w.push_back(probability);
                if w.len() > window_size {
                    w.pop_front();
                }
            }
        }
    }

    fn record_probability(&self, probability: f64) {
        let mut window = self.recent_probabilities.write();
        window.push_back(probability);
        if window.len() > self.config.min_samples_for_drift.max(10) {
            window.pop_front();
        }

        if window.len() >= self.config.min_samples_for_drift {
            let mean = window.iter().sum::<f64>() / window.len() as f64;
            let mut baseline = self.baseline_probability.write();
            if baseline.is_none() {
                *baseline = Some(mean);
            }
        }
    }
}

#[cfg(feature = "events")]
impl SpamEngine {
    /// Analyze an email and also produce a normalized security event.
    /// Requires the `events` feature flag (which enables the `mail-common` dep).
    pub fn analyze_with_event(
        &self,
        body: &str,
        headers: &[(String, String)],
        auth_results: Option<&str>,
        correlation: Option<mail_common::security::CorrelationContext>,
    ) -> (SpamVerdict, mail_common::security::SecurityEvent) {
        let verdict = self.analyze(body, headers, auth_results);
        let correlation =
            correlation.unwrap_or_else(mail_common::security::CorrelationContext::generated);

        let (action, severity) = match verdict.classification {
            SpamClass::Ham => (
                mail_common::security::SecurityAction::Allow,
                mail_common::security::SecuritySeverity::Info,
            ),
            SpamClass::Spam => (
                mail_common::security::SecurityAction::Quarantine,
                mail_common::security::SecuritySeverity::Medium,
            ),
            SpamClass::Reject => (
                mail_common::security::SecurityAction::Reject,
                mail_common::security::SecuritySeverity::High,
            ),
        };

        let risk_score = verdict.score.min(10.0);

        let mut event = mail_common::security::SecurityEvent::new(
            mail_common::security::SecuritySystem::Spam,
            action,
            severity,
            risk_score,
            format!(
                "Spam verdict={} score={:.2} bayes={:.2}",
                verdict.classification, verdict.score, verdict.bayesian_probability
            ),
            correlation,
        );

        if let Some((_, ip_value)) = headers.iter().find(|(name, _)| {
            name.eq_ignore_ascii_case("x-originating-ip")
                || name.eq_ignore_ascii_case("x-client-ip")
        }) {
            event
                .metadata
                .insert("src_ip".to_string(), ip_value.clone());
        }

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

        (verdict, event)
    }
}

impl Default for SpamEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trained_engine() -> SpamEngine {
        let engine = SpamEngine::new();
        // Train with some spam
        for _ in 0..10 {
            let _ =
                engine.train_spam("Buy viagra now! Million dollars free lottery winner act now");
            let _ = engine.train_spam("Nigerian prince needs your help wire transfer urgently");
            let _ = engine.train_spam("You have won congratulations claim your prize immediately");
        }
        // Train with some ham
        for _ in 0..10 {
            let _ = engine.train_ham("Hi team, please review the quarterly report attached");
            let _ = engine.train_ham("Meeting scheduled for Tuesday at 3pm in conference room B");
            let _ = engine.train_ham("The deployment pipeline is passing all tests now");
        }
        engine
    }

    #[test]
    fn test_obvious_spam() {
        let engine = trained_engine();
        let headers = vec![
            ("From".into(), "scammer@evil.tk".into()),
            ("Reply-To".into(), "money@different.com".into()),
        ];
        let body = "Congratulations! You have won a million dollars! \
                     Click here: https://bit.ly/scam to wire transfer now! \
                     Act now! Limited time! Urgent!!!!!!!";

        let verdict = engine.analyze(body, &headers, Some("spf=fail; dkim=fail"));
        assert!(
            matches!(verdict.classification, SpamClass::Spam | SpamClass::Reject),
            "Expected Spam or Reject, got {:?}",
            verdict.classification
        );
        assert!(verdict.score > 5.0, "Spam score: {}", verdict.score);
    }

    #[test]
    fn test_clean_email() {
        let engine = trained_engine();
        let headers = vec![
            ("From".into(), "alice@company.com".into()),
            ("Message-ID".into(), "<abc123@company.com>".into()),
            ("Date".into(), "Mon, 1 Jan 2024 00:00:00 +0000".into()),
            (
                "Received".into(),
                "from mx.company.com by mx2.company.com".into(),
            ),
        ];
        let body = "Hi Bob, I wanted to follow up on the project timeline we discussed. \
                     Can you send me the updated schedule by end of day? Thanks.";

        let verdict = engine.analyze(body, &headers, Some("spf=pass; dkim=pass; dmarc=pass"));
        assert_eq!(verdict.classification, SpamClass::Ham);
    }

    #[test]
    fn test_phishing_email() {
        let engine = trained_engine();
        let headers = vec![("From".into(), "security@bank-secure.tk".into())];
        let body = "Your account has been suspended. Verify your account immediately. \
                     Click here to login: http://192.168.1.50/bank/login \
                     Update your payment information to restore access. \
                     data:text/html;base64,PHNjcmlwdD4=";

        let verdict = engine.analyze(body, &headers, Some("spf=fail; dkim=none; dmarc=fail"));
        assert!(verdict.score > 5.0, "Phishing score: {}", verdict.score);
    }

    #[test]
    fn test_spam_class_display() {
        assert_eq!(SpamClass::Ham.to_string(), "HAM");
        assert_eq!(SpamClass::Spam.to_string(), "SPAM");
        assert_eq!(SpamClass::Reject.to_string(), "REJECT");
    }

    #[test]
    fn test_training_review_workflow() {
        let config = SpamConfig {
            enable_guarded_training: true,
            ..Default::default()
        };
        let engine = SpamEngine::with_config(config);

        engine.add_reviewer("sec-reviewer");
        let id = engine
            .submit_training_sample(TrainingLabel::Spam, "wire transfer now", "ops")
            .expect("queued");

        assert!(!engine.approve_training_sample(&id, "unauthorized"));
        assert!(engine.approve_training_sample(&id, "sec-reviewer"));
    }

    #[test]
    fn test_snapshot_and_rollback() {
        let engine = SpamEngine::new();
        let _ = engine.train_ham("team meeting schedule quarterly roadmap");
        let snap = engine.create_model_snapshot("baseline");
        let _ = engine.train_spam("buy now lottery winner free crypto");
        assert!(engine.rollback_to_snapshot(&snap));
    }

    // ── Security-fix regression tests ──

    #[test]
    fn test_dmarc_none_is_informational_not_full_penalty() {
        let engine = SpamEngine::new();
        // Engine-level DMARC policy penalties:dmarc=none is informational
        // (0.5), dmarc=fail carries the full 2.5.
        assert_eq!(engine.check_dmarc_policy(Some("dmarc=none")), 0.5);
        assert_eq!(engine.check_dmarc_policy(Some("dmarc=fail")), 2.5);
        assert_eq!(engine.check_dmarc_policy(Some("dmarc=pass")), 0.0);
        assert_eq!(engine.check_dmarc_policy(None), 0.0);

        // End-to-end:none must score strictly below fail on the same body.
        let none = engine.analyze("hello there friend", &[], Some("dmarc=none"));
        let fail = engine.analyze("hello there friend", &[], Some("dmarc=fail"));
        let pass = engine.analyze("hello there friend", &[], Some("dmarc=pass"));
        assert!(fail.score > none.score);
        // The engine penalty difference alone must be 2.0 (2.5 - 0.5).
        assert!(
            (fail.score - none.score) >= 2.0,
            "dmarc=fail must out-penalize dmarc=none by at least the 2.0 engine delta (delta={})",
            fail.score - none.score
        );
        // dmarc=none adds only the weak informational signal (plus whatever
        // the header analyzer independently contributes).
        assert!(
            none.score - pass.score <= 0.5 + 0.5,
            "dmarc=none delta must stay informational (delta={})",
            none.score - pass.score
        );
    }

    #[test]
    fn test_analyze_applies_custom_phrase_blocklists() {
        let config = crate::config::SpamConfig {
            custom_phrase_blocklists: vec![crate::config::CustomPhraseList {
                category: "internal-policy".into(),
                phrases: vec!["quuxblast offer".into()],
                weight: 2.0,
            }],
            ..Default::default()
        };
        let engine = SpamEngine::with_config(config);
        let verdict = engine.analyze("this message contains quuxblast offer inside", &[], None);
        assert!(
            verdict
                .content_score
                .findings
                .iter()
                .any(|f| f.id == "CUSTOM_PHRASE"),
            "analyze() must apply custom phrase blocklists like analyze_for_tenant: {:?}",
            verdict.content_score.findings
        );

        // Parity:analyze_for_tenant must produce the same content findings.
        let tenant_verdict = engine.analyze_for_tenant(
            "this message contains quuxblast offer inside",
            &[],
            None,
            "tenant-1",
        );
        assert!(tenant_verdict
            .content_score
            .findings
            .iter()
            .any(|f| f.id == "CUSTOM_PHRASE"));
    }

    #[test]
    fn test_tenant_classifier_map_is_bounded() {
        let engine = SpamEngine::new();
        for i in 0..(MAX_TENANT_CLASSIFIERS + 50) {
            engine.train_tenant_spam(&format!("tenant-{i}"), "buy pills now");
        }
        let count = engine.tenant_classifiers.read().len();
        assert!(
            count <= MAX_TENANT_CLASSIFIERS,
            "tenant classifier map must be LRU-bounded, got {}",
            count
        );
    }

    #[test]
    fn test_model_snapshots_are_bounded() {
        let engine = SpamEngine::new();
        let mut ids = Vec::new();
        for i in 0..(MAX_MODEL_SNAPSHOTS + 10) {
            ids.push(engine.create_model_snapshot(&format!("s{i}")));
        }
        let count = engine.model_snapshots.read().len();
        assert!(
            count <= MAX_MODEL_SNAPSHOTS,
            "snapshot map must be LRU-bounded, got {}",
            count
        );
        // The oldest snapshots were evicted; the newest must survive.
        assert!(!engine.model_snapshots.read().contains_key(&ids[0]));
        assert!(engine.model_snapshots.read().contains_key(ids.last().unwrap()));
    }
}
