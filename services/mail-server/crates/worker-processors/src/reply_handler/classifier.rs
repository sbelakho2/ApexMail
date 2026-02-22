//! Pattern-based reply classification using Aho-Corasick.

use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, Match};
use regex::Regex;

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
    out_of_office: vec![
        Regex::new(r"(?i)out of (?:the )?office").unwrap(),
        Regex::new(r"(?i)away from (?:my )?(?:desk|office|email)").unwrap(),
        Regex::new(r"(?i)on (?:annual |paid )?(?:leave|vacation|holiday|pto)").unwrap(),
        Regex::new(r"(?i)currently (?:out|away|traveling|unavailable)").unwrap(),
        Regex::new(r"(?i)limited access to email").unwrap(),
        Regex::new(r"(?i)auto[- ]?reply").unwrap(),
        Regex::new(r"(?i)automatic reply").unwrap(),
        Regex::new(r"(?i)i(?:'m| am) (?:currently )?(?:out|away|on leave)").unwrap(),
        Regex::new(r"(?i)will (?:be )?(?:back|return(?:ing)?|in the office)").unwrap(),
        Regex::new(r"(?i)maternity|paternity leave").unwrap(),
        Regex::new(r"(?i)(?:sick|medical) leave").unwrap(),
    ],
    not_interested: vec![
        Regex::new(r"(?i)not interested").unwrap(),
        Regex::new(r"(?i)no(?:t)? thank(?:s| you)").unwrap(),
        Regex::new(r"(?i)please remove (?:me|us)").unwrap(),
        Regex::new(r"(?i)don't contact (?:me|us)").unwrap(),
        Regex::new(r"(?i)stop (?:emailing|contacting|sending)").unwrap(),
        Regex::new(r"(?i)we(?:'re| are) not (?:looking|interested)").unwrap(),
        Regex::new(r"(?i)not a good fit").unwrap(),
        Regex::new(r"(?i)not (?:right|the right) time").unwrap(),
        Regex::new(r"(?i)pass(?:ing)? on this").unwrap(),
        Regex::new(r"(?i)we(?:'ll| will) pass").unwrap(),
        Regex::new(r"(?i)decline").unwrap(),
        Regex::new(r"(?i)not for us").unwrap(),
    ],
    interested: vec![
        Regex::new(r"(?i)(?:i(?:'m| am)|we(?:'re| are)) interested").unwrap(),
        Regex::new(r"(?i)tell (?:me|us) more").unwrap(),
        Regex::new(r"(?i)(?:can|could) you (?:send|share|provide)").unwrap(),
        Regex::new(r"(?i)(?:i|we) (?:would |'d )?like (?:to )?(?:learn|know|hear|see) more").unwrap(),
        Regex::new(r"(?i)sounds (?:interesting|great|good)").unwrap(),
        Regex::new(r"(?i)let(?:'s| us) (?:chat|talk|connect|discuss)").unwrap(),
        Regex::new(r"(?i)when (?:can|could) we (?:meet|talk|chat)").unwrap(),
        Regex::new(r"(?i)schedule (?:a )?(?:call|meeting|demo)").unwrap(),
        Regex::new(r"(?i)book (?:a )?(?:time|meeting|call)").unwrap(),
        Regex::new(r"(?i)(?:free|available) (?:for a )?(?:call|chat|meeting)").unwrap(),
    ],
    wrong_person: vec![
        Regex::new(r"(?i)(?:i(?:'m| am)|i) not the (?:right|correct) person").unwrap(),
        Regex::new(r"(?i)wrong (?:person|contact|department)").unwrap(),
        Regex::new(r"(?i)you (?:should|need to) (?:contact|reach out to|speak with)").unwrap(),
        Regex::new(r"(?i)try (?:contacting|reaching)").unwrap(),
        Regex::new(r"(?i)(?:forward|forwarding) (?:this )?to").unwrap(),
        Regex::new(r"(?i)no longer (?:work|at|with)").unwrap(),
        Regex::new(r"(?i)left the company").unwrap(),
        Regex::new(r"(?i)moved to (?:a )?(?:different|another)").unwrap(),
    ],
    unsubscribe: vec![
        Regex::new(r"(?i)unsubscribe").unwrap(),
        Regex::new(r"(?i)remove (?:me|my email|us)").unwrap(),
        Regex::new(r"(?i)opt[- ]?out").unwrap(),
        Regex::new(r"(?i)stop (?:sending|emailing)").unwrap(),
        Regex::new(r"(?i)take (?:me|us) off (?:your |the )?list").unwrap(),
        Regex::new(r"(?i)gdpr|ccpa|data (?:deletion|removal)").unwrap(),
        Regex::new(r"(?i)do not (?:email|contact)").unwrap(),
    ],
    meeting_request: vec![
        Regex::new(r"(?i)(?:schedule|book|set up) (?:a )?(?:call|meeting|demo|time)").unwrap(),
        Regex::new(r"(?i)(?:when|what time)(?:'s| is| are) (?:good|available)").unwrap(),
        Regex::new(r"(?i)(?:free|available) (?:on|this|next)").unwrap(),
        Regex::new(r"(?i)(?:let(?:'s| us)|can we) (?:meet|connect|chat|talk)").unwrap(),
        Regex::new(r"(?i)calendly|hubspot|zoom|teams").unwrap(),
    ],
    complaint: vec![
        Regex::new(r"(?i)complaint").unwrap(),
        Regex::new(r"(?i)disappointed").unwrap(),
        Regex::new(r"(?i)frustrated").unwrap(),
        Regex::new(r"(?i)unacceptable").unwrap(),
        Regex::new(r"(?i)terrible").unwrap(),
        Regex::new(r"(?i)awful").unwrap(),
        Regex::new(r"(?i)worst").unwrap(),
    ],
    spam: vec![
        Regex::new(r"(?i)spam").unwrap(),
        Regex::new(r"(?i)junk").unwrap(),
        Regex::new(r"(?i)unsolicited").unwrap(),
        Regex::new(r"(?i)report(?:ing)? (?:this )?as spam").unwrap(),
    ],
    positive: vec![
        Regex::new(r"(?i)thank(?:s| you)").unwrap(),
        Regex::new(r"(?i)great").unwrap(),
        Regex::new(r"(?i)excellent").unwrap(),
        Regex::new(r"(?i)awesome").unwrap(),
        Regex::new(r"(?i)perfect").unwrap(),
        Regex::new(r"(?i)love it").unwrap(),
        Regex::new(r"(?i)sounds good").unwrap(),
    ],
    negative: vec![
        Regex::new(r"(?i)no\b").unwrap(),
        Regex::new(r"(?i)not\b").unwrap(),
        Regex::new(r"(?i)don't").unwrap(),
        Regex::new(r"(?i)won't").unwrap(),
        Regex::new(r"(?i)can't").unwrap(),
        Regex::new(r"(?i)never").unwrap(),
        Regex::new(r"(?i)stop").unwrap(),
        Regex::new(r"(?i)remove").unwrap(),
    ],
});

/// Quick pattern phrases for Aho-Corasick fast initial scan.
static QUICK_PATTERNS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "out of office",
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
    ])
    .expect("Invalid Aho-Corasick patterns")
});

/// Classify a reply based on pattern matching.
pub fn classify(subject: &str, body: &str) -> ClassificationResult {
    let combined = format!("{} {}", subject, body);
    let text = combined.to_lowercase();

    // Quick scan for obvious patterns
    let quick_matches: Vec<Match> = QUICK_PATTERNS.find_iter(&text).collect();

    // Score each classification
    let mut scores: Vec<(ReplyClassification, usize, &str)> = Vec::new();

    // Out of office
    let ooo_matches: usize = PATTERNS
        .out_of_office
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if ooo_matches > 0 {
        scores.push((ReplyClassification::OutOfOffice, ooo_matches, "OOO patterns matched"));
    }

    // Not interested
    let ni_matches: usize = PATTERNS
        .not_interested
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if ni_matches > 0 {
        scores.push((ReplyClassification::NotInterested, ni_matches, "Not interested patterns matched"));
    }

    // Interested
    let int_matches: usize = PATTERNS
        .interested
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if int_matches > 0 {
        scores.push((ReplyClassification::Interested, int_matches, "Interest patterns matched"));
    }

    // Wrong person
    let wp_matches: usize = PATTERNS
        .wrong_person
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if wp_matches > 0 {
        scores.push((ReplyClassification::WrongPerson, wp_matches, "Wrong person patterns matched"));
    }

    // Unsubscribe
    let unsub_matches: usize = PATTERNS
        .unsubscribe
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if unsub_matches > 0 {
        scores.push((ReplyClassification::Unsubscribe, unsub_matches, "Unsubscribe patterns matched"));
    }

    // Meeting request (check before Interested since patterns overlap)
    let meet_matches: usize = PATTERNS
        .meeting_request
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if meet_matches > 0 {
        // Boost meeting request score to take precedence over generic "interested"
        scores.push((ReplyClassification::MeetingRequest, meet_matches + 10, "Meeting request patterns matched"));
    }

    // Complaint
    let comp_matches: usize = PATTERNS
        .complaint
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if comp_matches > 0 {
        scores.push((ReplyClassification::Complaint, comp_matches, "Complaint patterns matched"));
    }

    // Spam
    let spam_matches: usize = PATTERNS
        .spam
        .iter()
        .filter(|r| r.is_match(&combined))
        .count();
    if spam_matches > 0 {
        scores.push((ReplyClassification::Spam, spam_matches, "Spam patterns matched"));
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

    // Pick the best classification
    scores.sort_by(|a, b| b.1.cmp(&a.1));

    let (classification, match_count, reasoning) = scores
        .first()
        .map(|(c, n, r)| (*c, *n, *r))
        .unwrap_or((ReplyClassification::Unknown, 0, "No patterns matched"));

    // Calculate confidence (0.0 - 1.0)
    let confidence = match match_count {
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
        ReplyClassification::Interested | ReplyClassification::MeetingRequest | ReplyClassification::PositiveIntent => Urgency::High,
        ReplyClassification::NotInterested | ReplyClassification::WrongPerson => Urgency::Medium,
        _ => Urgency::Low,
    };

    ClassificationResult {
        classification,
        confidence,
        sub_type: None,
        extracted_data: ExtractedData {
            return_date: None, // Would need date parsing
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
fn build_suggested_action(classification: ReplyClassification, sentiment: Sentiment) -> SuggestedAction {
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
        ReplyClassification::MeetingRequest | ReplyClassification::PositiveIntent => SuggestedAction {
            action: ActionType::ScheduleDemo,
            parameters: serde_json::json!({ "priority": "high" }),
            auto_execute: false,
            priority: Urgency::High,
        },
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
        let result = classify("Re: Partnership", "Thanks, but we're not interested at this time.");
        assert_eq!(result.classification, ReplyClassification::NotInterested);
    }

    #[test]
    fn test_classify_interested() {
        let result = classify("Re: Your Product", "This sounds interesting! Can you tell me more?");
        assert_eq!(result.classification, ReplyClassification::Interested);
        assert!(matches!(result.suggested_action.action, ActionType::FlagSales));
    }

    #[test]
    fn test_classify_unsubscribe() {
        let result = classify("Unsubscribe", "Please unsubscribe me from your mailing list.");
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
        assert_eq!(result.extracted_data.meeting_request, true);
    }
}
