//! Reply classification facade — composes the three honest layers.
//!
//! 1. [`deterministic`](super::deterministic) — high-certainty header/syntax
//!    cases (DSN/bounces, Auto-Submitted/OOO, one-click unsubscribe, explicit
//!    stop requests). Runs first and wins.
//! 2. [`ai`](super::ai) — semantic classification for everything the
//!    deterministic layer could not prove. Provider-agnostic, with a
//!    never-guessing fallback on outage.
//! 3. [`policy`](super::policy) — the only place that turns a classification
//!    into an action.
//!
//! The legacy [`classify`] entry point (subject + body only, synchronous)
//! remains for compatibility: it runs the deterministic layer and then the
//! historical Aho-Corasick/pattern heuristics that predate the split. The
//! worker itself uses [`classify_full`], which is header-aware and async.
//!
//! # ReDoS Protection (O-16.11)
//!
//! Input is truncated to [`MAX_CLASSIFIER_INPUT_BYTES`] before any pattern
//! matching. The Aho-Corasick quick patterns guarantee O(n) matching; the
//! slower `regex::Regex` patterns only execute if at least one quick pattern
//! matched.

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use regex::Regex;
use tracing::warn;

use super::ai::{self, ReplyClassifier, AI_OUTAGE_REASON_PREFIX};
pub use super::deterministic::MAX_CLASSIFIER_INPUT_BYTES as CLASSIFIER_INPUT_CAP;
use super::deterministic::{self, DeterministicVerdict, MAX_CLASSIFIER_INPUT_BYTES};
use super::policy::{self, PolicyInput};
use super::types::{
    ActionType, AiClassification, ClassificationOutcome, ClassificationResult, ClassifierKind,
    ExtractedData, ReplyClassification, ReplyDisposition, ReplyInput, Sentiment, SuggestedAction,
    Urgency,
};

/// Compiled pattern matchers for the historical heuristic layer.
struct PatternSet {
    out_of_office: Vec<Regex>,
    not_interested: Vec<Regex>,
    interested: Vec<Regex>,
    wrong_person: Vec<Regex>,
    unsubscribe: Vec<Regex>,
    meeting_request: Vec<Regex>,
    complaint: Vec<Regex>,
    spam: Vec<Regex>,
    positive: Vec<Regex>,
    negative: Vec<Regex>,
}

static PATTERNS: LazyLock<PatternSet> = LazyLock::new(|| PatternSet {
    out_of_office: compile_regexes(&[
        r"(?i)out of (?:the )?office",
        r"(?i)away from (?:my )?(?:desk|office|email)",
        r"(?i)on (?:annual |paid )?(?:leave|vacation|holiday|pto)",
        r"(?i)currently (?:out|away|traveling|unavailable)",
        r"(?i)limited access to email",
        r"(?i)auto[- ]?reply",
        r"(?i)automatic reply",
        r"(?i)i(?:'m| am) (?:currently )?(?:out|away|on leave)",
        r"(?i)will (?:be )?(?:back|return(?:ing)?|in the office)",
        r"(?i)maternity|paternity leave",
        r"(?i)(?:sick|medical) leave",
    ]),
    not_interested: compile_regexes(&[
        r"(?i)not interested",
        r"(?i)no(?:t)? thank(?:s| you)",
        r"(?i)please remove (?:me|us)",
        r"(?i)don't contact (?:me|us)",
        r"(?i)stop (?:emailing|contacting|sending)",
        r"(?i)we(?:'re| are) not (?:looking|interested)",
        r"(?i)not a good fit",
        r"(?i)not (?:right|the right) time",
        r"(?i)pass(?:ing)? on this",
        r"(?i)we(?:'ll| will) pass",
        r"(?i)decline",
        r"(?i)not for us",
    ]),
    interested: compile_regexes(&[
        r"(?i)(?:i(?:'m| am)|we(?:'re| are)) interested",
        r"(?i)tell (?:me|us) more",
        r"(?i)(?:can|could) you (?:send|share|provide)",
        r"(?i)(?:i|we) (?:would |'d )?like (?:to )?(?:learn|know|hear|see) more",
        r"(?i)sounds (?:interesting|great|good)",
        r"(?i)let(?:'s| us) (?:chat|talk|connect|discuss)",
        r"(?i)when (?:can|could) we (?:meet|talk|chat)",
        r"(?i)schedule (?:a )?(?:call|meeting|demo)",
        r"(?i)book (?:a )?(?:time|meeting|call)",
        r"(?i)(?:free|available) (?:for a )?(?:call|chat|meeting)",
    ]),
    wrong_person: compile_regexes(&[
        r"(?i)(?:i(?:'m| am)|i) not the (?:right|correct) person",
        r"(?i)wrong (?:person|contact|department)",
        r"(?i)you (?:should|need to) (?:contact|reach out to|speak with)",
        r"(?i)try (?:contacting|reaching)",
        r"(?i)(?:forward|forwarding) (?:this )?to",
        r"(?i)no longer (?:work|at|with)",
        r"(?i)left the company",
        r"(?i)moved to (?:a )?(?:different|another)",
    ]),
    unsubscribe: compile_regexes(&[
        r"(?i)unsubscribe",
        r"(?i)remove (?:me|my email|us)",
        r"(?i)opt[- ]?out",
        r"(?i)stop (?:sending|emailing)",
        r"(?i)take (?:me|us) off (?:your |the )?list",
        r"(?i)gdpr|ccpa|data (?:deletion|removal)",
        r"(?i)do not (?:email|contact)",
    ]),
    meeting_request: compile_regexes(&[
        r"(?i)(?:schedule|book|set up) (?:a )?(?:call|meeting|demo|time)",
        r"(?i)(?:when|what time)(?:'s| is| are) (?:good|available)",
        r"(?i)(?:free|available) (?:on|this|next)",
        r"(?i)(?:let(?:'s| us)|can we) (?:meet|connect|chat|talk)",
        r"(?i)calendly|hubspot|zoom|teams",
    ]),
    complaint: compile_regexes(&[
        r"(?i)complaint",
        r"(?i)disappointed",
        r"(?i)frustrated",
        r"(?i)unacceptable",
        r"(?i)terrible",
        r"(?i)awful",
        r"(?i)worst",
    ]),
    spam: compile_regexes(&[
        r"(?i)spam",
        r"(?i)junk",
        r"(?i)unsolicited",
        r"(?i)report(?:ing)? (?:this )?as spam",
    ]),
    positive: compile_regexes(&[
        r"(?i)thank(?:s| you)",
        r"(?i)great",
        r"(?i)excellent",
        r"(?i)awesome",
        r"(?i)perfect",
        r"(?i)love it",
        r"(?i)sounds good",
    ]),
    negative: compile_regexes(&[
        r"(?i)no\b",
        r"(?i)not\b",
        r"(?i)don't",
        r"(?i)won't",
        r"(?i)can't",
        r"(?i)never",
        r"(?i)stop",
        r"(?i)remove",
    ]),
});

/// Quick pattern phrases for Aho-Corasick fast initial scan.
static QUICK_PATTERNS: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    let patterns = [
        "out of office",
        "out of the office",
        "not interested",
        "interested",
        "tell me more",
        "wrong person",
        "unsubscribe",
        "schedule a call",
        "book a meeting",
        "auto-reply",
        "automatic reply",
        "on vacation",
        "on leave",
        "remove me",
        "stop emailing",
        "opt out",
    ];
    match AhoCorasick::new(patterns) {
        Ok(ac) => Some(ac),
        Err(e) => {
            warn!(error = %e, "Invalid Aho-Corasick patterns; disabling quick scan");
            None
        }
    }
});

fn compile_regexes(patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|pattern| match Regex::new(pattern) {
            Ok(regex) => Some(regex),
            Err(e) => {
                warn!(pattern = %pattern, error = %e, "Invalid regex pattern");
                None
            }
        })
        .collect()
}

/// Classify a reply from subject + body (legacy synchronous entry point).
///
/// Runs the deterministic layer first; if nothing is provable there, falls
/// back to the historical pattern heuristic. Callers that also have headers
/// should use [`classify_full`] — the worker does.
pub fn classify(subject: &str, body: &str) -> ClassificationResult {
    let input = ReplyInput::new(subject, body);
    if let Some(verdict) = deterministic::classify(&input) {
        return result_from_verdict(&verdict);
    }
    legacy_heuristic_classify(subject, body)
}

/// Full three-layer classification: deterministic first, then the AI layer
/// (or its never-guessing fallback). `ai` is typically an
/// [`super::ai::HttpReplyClassifier`] or the static fallback.
pub async fn classify_full(ai: &dyn ReplyClassifier, input: &ReplyInput) -> ClassificationOutcome {
    if let Some(verdict) = deterministic::classify(input) {
        return outcome_from_verdict(verdict);
    }

    let classification = ai::classify_or_fallback(ai, input).await;
    outcome_from_ai(classification)
}

/// Build the legacy-shaped result for a deterministic verdict.
fn result_from_verdict(verdict: &DeterministicVerdict) -> ClassificationResult {
    let decision = policy::decide(
        PolicyInput::new(verdict.disposition, verdict.confidence)
            .with_return_date(verdict.return_date),
        chrono::Utc::now(),
    );
    build_result(
        decision.disposition,
        verdict.confidence,
        decision.legacy_action,
        verdict.reasoning.clone(),
        verdict.return_date,
    )
}

fn outcome_from_verdict(verdict: DeterministicVerdict) -> ClassificationOutcome {
    let decision = policy::decide(
        PolicyInput::new(verdict.disposition, verdict.confidence)
            .with_return_date(verdict.return_date),
        chrono::Utc::now(),
    );
    let result = build_result(
        decision.disposition,
        verdict.confidence,
        decision.legacy_action,
        verdict.reasoning.clone(),
        verdict.return_date,
    );
    ClassificationOutcome {
        disposition: decision.disposition,
        classifier: ClassifierKind::Deterministic,
        result,
        evidence: verdict.evidence,
        model_version: None,
        prompt_version: None,
        return_date: verdict.return_date,
        downgraded_from: None,
    }
}

fn outcome_from_ai(classification: AiClassification) -> ClassificationOutcome {
    // The never-guessing fallback is itself deterministic (it is a pure
    // function of the outage), so an outage result is recorded as
    // `deterministic` with the outage named in the reasoning — never as a
    // model verdict.
    let outage = classification
        .reasoning
        .starts_with(AI_OUTAGE_REASON_PREFIX);
    let decision = policy::decide(
        PolicyInput::new(classification.disposition, classification.confidence),
        chrono::Utc::now(),
    );
    let downgraded_from = decision.downgraded.map(|_| classification.disposition);
    let reasoning = match decision.downgraded {
        Some(reason) => format!(
            "{} (observed '{}' at confidence {:.2}, downgraded: {})",
            classification.reasoning,
            classification.disposition.as_str(),
            decision.confidence,
            reason.as_str()
        ),
        None => classification.reasoning.clone(),
    };
    let result = build_result(
        decision.disposition,
        decision.confidence,
        decision.legacy_action,
        reasoning,
        None,
    );
    ClassificationOutcome {
        disposition: decision.disposition,
        classifier: if outage {
            ClassifierKind::Deterministic
        } else {
            ClassifierKind::Ai
        },
        result,
        evidence: classification.evidence,
        model_version: classification.model_version,
        prompt_version: classification.prompt_version,
        return_date: None,
        downgraded_from,
    }
}

/// Assemble the legacy result plus sentiment/urgency from the final
/// disposition.
fn build_result(
    disposition: ReplyDisposition,
    confidence: f64,
    suggested_action: SuggestedAction,
    reasoning: String,
    return_date: Option<chrono::DateTime<chrono::Utc>>,
) -> ClassificationResult {
    ClassificationResult {
        classification: ReplyClassification::from(disposition),
        confidence,
        sub_type: None,
        extracted_data: ExtractedData {
            return_date,
            referred_contact: None,
            meeting_request: disposition == ReplyDisposition::MeetingRequest,
            sentiment: sentiment_for(disposition),
            urgency: urgency_for(disposition),
        },
        suggested_action,
        reasoning,
    }
}

fn sentiment_for(disposition: ReplyDisposition) -> Sentiment {
    match disposition {
        ReplyDisposition::Positive
        | ReplyDisposition::MeetingRequest
        | ReplyDisposition::Question
        | ReplyDisposition::Referral => Sentiment::Positive,
        ReplyDisposition::NotInterested
        | ReplyDisposition::Unsubscribe
        | ReplyDisposition::Complaint
        | ReplyDisposition::BounceHard => Sentiment::Negative,
        _ => Sentiment::Neutral,
    }
}

fn urgency_for(disposition: ReplyDisposition) -> Urgency {
    match disposition {
        ReplyDisposition::Unsubscribe
        | ReplyDisposition::Complaint
        | ReplyDisposition::Positive
        | ReplyDisposition::MeetingRequest
        | ReplyDisposition::Question
        | ReplyDisposition::Referral => Urgency::High,
        ReplyDisposition::NotInterested | ReplyDisposition::BounceHard => Urgency::Medium,
        _ => Urgency::Low,
    }
}

/// The historical heuristic classifier, unchanged in behaviour. Only used by
/// the legacy [`classify`] path when the deterministic layer proves nothing;
/// the worker's async path uses the AI layer instead of these patterns.
fn legacy_heuristic_classify(subject: &str, body: &str) -> ClassificationResult {
    let combined = format!("{} {}", subject, body);
    let combined = if combined.len() > MAX_CLASSIFIER_INPUT_BYTES {
        let truncated: String = combined
            .chars()
            .take(MAX_CLASSIFIER_INPUT_BYTES / 2)
            .collect();
        warn!(
            input_len = combined.len(),
            max = MAX_CLASSIFIER_INPUT_BYTES,
            "Classifier input truncated for ReDoS protection"
        );
        truncated
    } else {
        combined
    };
    let text = combined.to_lowercase();

    if let Some(quick_patterns) = QUICK_PATTERNS.as_ref() {
        let quick_match_count = quick_patterns.find_iter(&text).count();
        if quick_match_count == 0 {
            // No obvious patterns matched - return Unknown early to save regex work
            return ClassificationResult {
                classification: ReplyClassification::Unknown,
                confidence: 0.3,
                sub_type: None,
                extracted_data: ExtractedData::default(),
                reasoning: "No quick patterns matched".to_string(),
                suggested_action: build_suggested_action(
                    ReplyClassification::Unknown,
                    Sentiment::Neutral,
                ),
            };
        }
    }

    // Score each classification
    // priority_score is for sorting; actual_matches is for confidence calculation
    let mut scores: Vec<(ReplyClassification, usize, usize, &str)> = Vec::with_capacity(8);

    // Out of office
    let ooo_matches: usize = PATTERNS
        .out_of_office
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if ooo_matches > 0 {
        scores.push((
            ReplyClassification::OutOfOffice,
            ooo_matches,
            ooo_matches,
            "OOO patterns matched",
        ));
    }

    // Not interested
    let ni_matches: usize = PATTERNS
        .not_interested
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if ni_matches > 0 {
        scores.push((
            ReplyClassification::NotInterested,
            ni_matches,
            ni_matches,
            "Not interested patterns matched",
        ));
    }

    // Interested
    let int_matches: usize = PATTERNS
        .interested
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if int_matches > 0 {
        scores.push((
            ReplyClassification::Interested,
            int_matches,
            int_matches,
            "Interest patterns matched",
        ));
    }

    // Wrong person
    let wp_matches: usize = PATTERNS
        .wrong_person
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if wp_matches > 0 {
        scores.push((
            ReplyClassification::WrongPerson,
            wp_matches,
            wp_matches,
            "Wrong person patterns matched",
        ));
    }

    // Unsubscribe
    let unsub_matches: usize = PATTERNS
        .unsubscribe
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if unsub_matches > 0 {
        scores.push((
            ReplyClassification::Unsubscribe,
            unsub_matches,
            unsub_matches,
            "Unsubscribe patterns matched",
        ));
    }

    // Meeting request (check before Interested since patterns overlap)
    let meet_matches: usize = PATTERNS
        .meeting_request
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if meet_matches > 0 {
        // Boost priority to take precedence over generic "interested", but keep actual matches for confidence
        scores.push((
            ReplyClassification::MeetingRequest,
            meet_matches + 10,
            meet_matches,
            "Meeting request patterns matched",
        ));
    }

    // Complaint
    let comp_matches: usize = PATTERNS
        .complaint
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if comp_matches > 0 {
        scores.push((
            ReplyClassification::Complaint,
            comp_matches,
            comp_matches,
            "Complaint patterns matched",
        ));
    }

    // Spam
    let spam_matches: usize = PATTERNS
        .spam
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if spam_matches > 0 {
        scores.push((
            ReplyClassification::Spam,
            spam_matches,
            spam_matches,
            "Spam patterns matched",
        ));
    }

    // Determine sentiment
    let positive_count: usize = PATTERNS
        .positive
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    let negative_count: usize = PATTERNS
        .negative
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();

    let sentiment = if positive_count > negative_count * 2 {
        Sentiment::Positive
    } else if negative_count > positive_count * 2 {
        Sentiment::Negative
    } else {
        Sentiment::Neutral
    };

    // Pick the best classification (sort by priority score)
    scores.sort_by_key(|(_, priority, _, _)| std::cmp::Reverse(*priority));

    // Extract:classification, _priority, actual_matches, reasoning
    let (classification, actual_matches, reasoning) = scores
        .first()
        .map(|(c, _priority, actual, r)| (*c, *actual, *r))
        .unwrap_or((ReplyClassification::Unknown, 0, "No patterns matched"));

    // Calculate confidence based on actual pattern matches (not boosted priority)
    let confidence = match actual_matches {
        0 => 0.3,
        1 => 0.5,
        2 => 0.7,
        3 => 0.85,
        _ => 0.95,
    };

    // Build suggested action
    let suggested_action = build_suggested_action(classification, sentiment);

    // Determine urgency
    let urgency = match classification {
        ReplyClassification::Unsubscribe | ReplyClassification::Complaint => Urgency::High,
        ReplyClassification::Interested
        | ReplyClassification::MeetingRequest
        | ReplyClassification::PositiveIntent => Urgency::High,
        ReplyClassification::NotInterested | ReplyClassification::WrongPerson => Urgency::Medium,
        _ => Urgency::Low,
    };

    ClassificationResult {
        classification,
        confidence,
        sub_type: None,
        extracted_data: ExtractedData {
            return_date: None,      // Would need date parsing
            referred_contact: None, // Would need entity extraction
            meeting_request: classification == ReplyClassification::MeetingRequest,
            sentiment,
            urgency,
        },
        suggested_action,
        reasoning: reasoning.to_string(),
    }
}

/// Build suggested action based on classification (legacy heuristic path).
fn build_suggested_action(
    classification: ReplyClassification,
    _sentiment: Sentiment,
) -> SuggestedAction {
    match classification {
        ReplyClassification::OutOfOffice => SuggestedAction {
            action: ActionType::Snooze,
            parameters: serde_json::json!({ "duration_days": 7 }),
            auto_execute: true,
            priority: Urgency::Low,
        },
        ReplyClassification::NotInterested => SuggestedAction {
            action: ActionType::Suppress,
            parameters: serde_json::json!({ "reason": "not_interested" }),
            auto_execute: false, // Require confirmation
            priority: Urgency::Medium,
        },
        ReplyClassification::Interested | ReplyClassification::TellMeMore => SuggestedAction {
            action: ActionType::FlagSales,
            parameters: serde_json::json!({ "flag": "interested", "priority": "high" }),
            auto_execute: true,
            priority: Urgency::High,
        },
        ReplyClassification::WrongPerson => SuggestedAction {
            action: ActionType::RequestReferral,
            parameters: serde_json::json!({}),
            auto_execute: false,
            priority: Urgency::Medium,
        },
        ReplyClassification::Unsubscribe => SuggestedAction {
            action: ActionType::Unsubscribe,
            parameters: serde_json::json!({}),
            auto_execute: true,
            priority: Urgency::High,
        },
        ReplyClassification::MeetingRequest | ReplyClassification::PositiveIntent => {
            SuggestedAction {
                action: ActionType::ScheduleDemo,
                parameters: serde_json::json!({ "priority": "high" }),
                auto_execute: false,
                priority: Urgency::High,
            }
        }
        ReplyClassification::Complaint => SuggestedAction {
            action: ActionType::Escalate,
            parameters: serde_json::json!({ "reason": "complaint" }),
            auto_execute: true,
            priority: Urgency::High,
        },
        ReplyClassification::Spam => SuggestedAction {
            action: ActionType::Ignore,
            parameters: serde_json::json!({}),
            auto_execute: true,
            priority: Urgency::Low,
        },
        _ => SuggestedAction {
            action: ActionType::Ignore,
            parameters: serde_json::json!({}),
            auto_execute: false,
            priority: Urgency::Low,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply_handler::ai::{ClassifyError, ReplyClassifier};
    use async_trait::async_trait;

    // ── Existing tests, converted to the new module layout ───────────

    #[test]
    fn test_classify_out_of_office() {
        let result = classify(
            "Re: Meeting Request",
            "I am currently out of the office and will return on Monday.",
        );
        assert_eq!(result.classification, ReplyClassification::OutOfOffice);
        assert!(result.confidence > 0.4);
    }

    #[test]
    fn test_classify_not_interested() {
        let result = classify(
            "Re: Partnership",
            "Thanks, but we're not interested at this time.",
        );
        assert_eq!(result.classification, ReplyClassification::NotInterested);
    }

    #[test]
    fn test_classify_interested() {
        let result = classify(
            "Re: Your Product",
            "This sounds interesting! Can you tell me more?",
        );
        assert_eq!(result.classification, ReplyClassification::Interested);
        assert!(matches!(
            result.suggested_action.action,
            ActionType::FlagSales
        ));
    }

    #[test]
    fn test_classify_unsubscribe() {
        let result = classify(
            "Unsubscribe",
            "Please unsubscribe me from your mailing list.",
        );
        assert_eq!(result.classification, ReplyClassification::Unsubscribe);
        assert!(result.suggested_action.auto_execute);
    }

    #[test]
    fn test_classify_meeting_request() {
        let result = classify(
            "Re: Demo Request",
            "I'd love to schedule a call. When are you available?",
        );
        assert_eq!(result.classification, ReplyClassification::MeetingRequest);
        assert!(result.extracted_data.meeting_request);
    }

    // ── The three-layer composition ──────────────────────────────────

    struct ErroringClassifier;
    #[async_trait]
    impl ReplyClassifier for ErroringClassifier {
        async fn classify(&self, _input: &ReplyInput) -> Result<AiClassification, ClassifyError> {
            Err(ClassifyError::Transport("connection refused".to_string()))
        }
    }

    #[tokio::test]
    async fn full_classification_uses_deterministic_first() {
        let input = ReplyInput::new(
            "Re: proposal",
            "This sounds great — can we schedule a call?",
        )
        .with_header("Auto-Submitted", "auto-replied");
        let outcome = classify_full(&ErroringClassifier, &input).await;
        assert_eq!(outcome.disposition, ReplyDisposition::OutOfOffice);
        assert_eq!(outcome.classifier, ClassifierKind::Deterministic);
        assert_eq!(
            outcome.result.classification,
            ReplyClassification::OutOfOffice
        );
        assert!(outcome
            .evidence
            .iter()
            .any(|e| e.kind == "header" && e.value == "auto-replied"));
    }

    #[tokio::test]
    async fn full_classification_falls_back_to_unknown_on_ai_outage() {
        let input = ReplyInput::new("Re: proposal", "vaguely positive vibes");
        let outcome = classify_full(&ErroringClassifier, &input).await;
        assert_eq!(outcome.disposition, ReplyDisposition::Unknown);
        assert_eq!(outcome.classifier, ClassifierKind::Deterministic);
        assert_eq!(outcome.result.confidence, 0.0);
        assert!(outcome.result.reasoning.contains(AI_OUTAGE_REASON_PREFIX));
        assert_ne!(
            outcome.result.classification,
            ReplyClassification::PositiveIntent
        );
    }

    #[tokio::test]
    async fn deterministic_stop_request_wins_over_ai() {
        // Even a classifier that would say "positive" must not be consulted
        // for an explicit unsubscribe.
        struct AlwaysPositive;
        #[async_trait]
        impl ReplyClassifier for AlwaysPositive {
            async fn classify(
                &self,
                _input: &ReplyInput,
            ) -> Result<AiClassification, ClassifyError> {
                Ok(AiClassification {
                    disposition: ReplyDisposition::Positive,
                    confidence: 1.0,
                    reasoning: String::new(),
                    model_version: None,
                    prompt_version: None,
                    evidence: vec![],
                })
            }
        }
        let input = ReplyInput::new("Re: list", "please unsubscribe me");
        let outcome = classify_full(&AlwaysPositive, &input).await;
        assert_eq!(outcome.disposition, ReplyDisposition::Unsubscribe);
        assert_eq!(outcome.classifier, ClassifierKind::Deterministic);
    }

    #[tokio::test]
    async fn low_confidence_ai_result_downgrades_in_the_full_path() {
        struct Hesitant;
        #[async_trait]
        impl ReplyClassifier for Hesitant {
            async fn classify(
                &self,
                _input: &ReplyInput,
            ) -> Result<AiClassification, ClassifyError> {
                Ok(AiClassification {
                    disposition: ReplyDisposition::Unsubscribe,
                    confidence: 0.2,
                    reasoning: "maybe".into(),
                    model_version: Some("test".into()),
                    prompt_version: None,
                    evidence: vec![],
                })
            }
        }
        let outcome = classify_full(&Hesitant, &ReplyInput::new("Re: hi", "hmm")).await;
        assert_eq!(outcome.disposition, ReplyDisposition::Unknown);
        assert_eq!(outcome.downgraded_from, Some(ReplyDisposition::Unsubscribe));
        assert!(
            outcome.result.suggested_action.action == ActionType::Ignore
                || !outcome.result.suggested_action.auto_execute,
            "a downgraded classification must not auto-suppress"
        );
        assert!(outcome.result.reasoning.contains("downgraded"));
    }

    #[test]
    fn legacy_result_projection_maps_every_disposition() {
        for disposition in ReplyDisposition::ALL {
            let legacy = ReplyClassification::from(disposition);
            assert!(!legacy.as_str().is_empty());
        }
        assert_eq!(
            ReplyClassification::from(ReplyDisposition::OutOfOffice).as_str(),
            "out_of_office"
        );
        assert_eq!(
            ReplyClassification::from(ReplyDisposition::BounceHard).as_str(),
            "bounce"
        );
    }

    #[test]
    fn input_cap_is_reexported() {
        assert_eq!(CLASSIFIER_INPUT_CAP, MAX_CLASSIFIER_INPUT_BYTES);
    }
}
