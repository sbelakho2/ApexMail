//! Pattern-based reply classification using Aho-Corasick.
//!
//! # ReDoS Protection (O-16.11)
//!
//! This module mitigates regex denial-of-service (ReDoS) through:
//!
//! 1. **Input length capping** — The combined `subject + body` text is truncated
//!    to `MAX_CLASSIFIER_INPUT_BYTES` before any pattern matching, preventing
//!    attackers from submitting multi-megabyte payloads that trigger pathological
//!    backtracking.
//! 2. **Aho-Corasick pre-filter** — Quick patterns use `aho_corasick::AhoCorasick`
//!    which guarantees O(n) matching (no backtracking). The slower `regex::Regex`
//!    patterns only execute if at least one quick pattern matched, providing a
//!    natural rate limit on expensive matching.
//! 3. **Synchronous timeout note** — If called from an async context, the caller
//!    should wrap `classify()` in `tokio::task::spawn_blocking` with a timeout.
//!    The function itself remains synchronous to maintain API compatibility,
//!    but the input length cap prevents the worst-case ReDoS scenarios.

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use regex::Regex;
use tracing::warn;

/// Maximum combined (subject + body) input size for the classifier (O-16.11).
/// Prevents ReDoS attacks via pathological inputs > 100 KB.
const MAX_CLASSIFIER_INPUT_BYTES: usize = 1024 * 100; // 100 KB

use super::types::{
    ActionType, ClassificationResult, ExtractedData, ReplyClassification, Sentiment,
    SuggestedAction, Urgency,
};

/// Compiled pattern matchers for each classification.
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

/// Classify a reply based on pattern matching.
///
/// O-16.11: Input is truncated to `MAX_CLASSIFIER_INPUT_BYTES` before any
/// pattern matching to prevent ReDoS via pathological inputs.
pub fn classify(subject: &str, body: &str) -> ClassificationResult {
    // O-16.11: Cap input length to prevent ReDoS attacks. The Aho-Corasick
    // quick patterns (O(n) guaranteed) run first; regex patterns only execute
    // if quick patterns match, which provides a natural rate limit.
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

/// Build suggested action based on classification.
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
}
