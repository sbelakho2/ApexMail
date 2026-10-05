//! Cross-crate contract tests for the reply classifier — the worker
//! (`worker-processors::reply_handler::ai`) and the AI service
//! (`ai_service::reply_classify`) are separate trust domains that must agree
//! on the wire, byte for byte. Each side has its own unit tests; THIS file is
//! the one place both are in scope, so a drift in the taxonomy, the prompt
//! version, or the response shape fails here rather than degrading the reply
//! pipeline into permanent Unknown classifications at runtime.

use worker_processors::reply_handler::{
    HttpReplyClassifier, ReplyDisposition, ReplyInput, AI_PROMPT_VERSION,
};

/// The canonical 11-disposition taxonomy is the same list on both sides —
/// the worker's request enumerates it and the service validates against it.
#[test]
fn taxonomy_matches_the_worker_disposition_enum() {
    let worker: Vec<&str> = ReplyDisposition::ALL.iter().map(|d| d.as_str()).collect();
    let service: Vec<&str> = ai_service::reply_classify::TAXONOMY.to_vec();
    assert_eq!(
        service, worker,
        "ai-service TAXONOMY drifted from ReplyDisposition::ALL — the service would \
         validate requests against a taxonomy the worker cannot parse"
    );
}

/// The prompt identity recorded on classifications must agree; a bump on one
/// side without the other silently mis-labels every audit row.
#[test]
fn prompt_versions_agree() {
    assert_eq!(
        ai_service::reply_classify::PROMPT_VERSION,
        AI_PROMPT_VERSION,
        "prompt version drift between the service and the worker client"
    );
}

/// The service's serialized response is exactly what the worker parses —
/// bare object, all fields, confidence in range. This is the contract the
/// plan requires ("contract tests against the exact client shape").
#[test]
fn service_response_parses_with_the_worker_client() {
    let response = ai_service::reply_classify::ReplyClassifyResponse {
        disposition: "meeting_request".to_string(),
        confidence: 0.82,
        reasoning: "asks to talk Thursday".to_string(),
        model_version: Some("apexmail-reply-2026-10".to_string()),
        prompt_version: ai_service::reply_classify::PROMPT_VERSION.to_string(),
        evidence: vec![ai_service::reply_classify::ClassifierEvidence {
            kind: "token".to_string(),
            key: "meeting".to_string(),
            value: "talk Thursday".to_string(),
        }],
        objection_class: None,
    };
    let wire = serde_json::to_value(&response).expect("serialize");
    let parsed =
        HttpReplyClassifier::parse_response(&wire).expect("worker parses the service shape");
    assert_eq!(parsed.disposition, ReplyDisposition::MeetingRequest);
    assert!((parsed.confidence - 0.82).abs() < f64::EPSILON);
    assert_eq!(parsed.evidence.len(), 1);
    assert_eq!(
        parsed.prompt_version.as_deref(),
        Some(AI_PROMPT_VERSION),
        "the recorded prompt version round-trips"
    );
    assert_eq!(
        parsed.model_version.as_deref(),
        Some("apexmail-reply-2026-10")
    );
}

/// The objection sub-label (§5.5) is an ADDITIVE field: the worker's parser
/// must accept a response that carries it (and ignore it until the objection
/// tier consumes it) rather than failing the whole classification.
#[test]
fn objection_class_field_is_forward_compatible() {
    let response = ai_service::reply_classify::ReplyClassifyResponse {
        disposition: "not_interested".to_string(),
        confidence: 0.71,
        reasoning: "declines on price".to_string(),
        model_version: None,
        prompt_version: ai_service::reply_classify::PROMPT_VERSION.to_string(),
        evidence: vec![],
        objection_class: Some("price".to_string()),
    };
    let wire = serde_json::to_value(&response).expect("serialize");
    assert_eq!(wire["objection_class"], "price");
    let parsed = HttpReplyClassifier::parse_response(&wire)
        .expect("an unknown additive field must not break the contract");
    assert_eq!(parsed.disposition, ReplyDisposition::NotInterested);
}

/// Every canonical disposition the service may return is one the worker can
/// parse — and the service's own validation refuses anything else.
#[test]
fn every_service_disposition_round_trips_through_the_worker() {
    for disposition in ai_service::reply_classify::TAXONOMY {
        let response = ai_service::reply_classify::ReplyClassifyResponse {
            disposition: disposition.to_string(),
            confidence: 0.5,
            reasoning: String::new(),
            model_version: None,
            prompt_version: ai_service::reply_classify::PROMPT_VERSION.to_string(),
            evidence: vec![],
            objection_class: None,
        };
        let wire = serde_json::to_value(&response).expect("serialize");
        let parsed = HttpReplyClassifier::parse_response(&wire)
            .unwrap_or_else(|error| panic!("worker cannot parse '{disposition}': {error}"));
        assert_eq!(parsed.disposition.as_str(), disposition);
    }
    // And the service refuses a disposition outside the canonical list.
    let error = ai_service::reply_classify::parse_classifier_output(
        r#"{"disposition": "vibes", "confidence": 0.9}"#,
    )
    .expect_err("outside-taxonomy must be refused, not passed through");
    assert!(
        error.message.contains("outside the taxonomy"),
        "{}",
        error.message
    );
}

/// `ReplyInput` carries the tenant for the header the service requires; the
/// default (no tenant) must be expressible so NULL-tenant rows still work.
#[test]
fn reply_input_carries_the_rate_governor_tenant() {
    let input = ReplyInput::new("s", "b").with_tenant(Some("ten_abc"));
    assert_eq!(input.tenant_id.as_deref(), Some("ten_abc"));
    let input = ReplyInput::new("s", "b");
    assert_eq!(input.tenant_id, None, "no tenant must stay expressible");
}
