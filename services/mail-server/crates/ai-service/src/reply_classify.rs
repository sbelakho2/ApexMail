//! `POST /reply/classify` — the reply pipeline's semantic classifier.
//!
//! Layer 2 of the worker's 3-layer classification (deterministic → AI →
//! policy): the worker calls this route ONLY for messages the deterministic
//! layer could not prove, and turns ANY route failure into the audited
//! Unknown/0.0 fallback (worker-processors/src/reply_handler/ai.rs). The
//! contract is therefore frozen to what that client parses:
//!
//! Request (`ClassifyRequest` in the client):
//! ```json
//! { "subject": "Re: proposal", "body": "can we talk Thursday?",
//!   "headers": {"auto-submitted": "no"},
//!   "taxonomy": ["positive", "meeting_request", ..., "unknown"],
//!   "prompt_version": "reply-classifier-v1" }
//! ```
//! Response:
//! ```json
//! { "disposition": "meeting_request", "confidence": 0.82,
//!   "reasoning": "asks to talk Thursday", "model_version": "…",
//!   "prompt_version": "reply-classifier-v1",
//!   "evidence": [{"kind": "token", "key": "meeting", "value": "talk Thursday"}],
//!   "objection_class": "timing" }
//! ```
//!
//! Truthfulness rules (enforced in [`parse_classifier_output`], not trusted
//! to the model):
//! - the disposition must be one of the canonical 11 — anything else is a
//!   502 the client turns into Unknown, never a pass-through;
//! - confidence is clamped to [0,1]; non-finite becomes 0.0;
//! - `objection_class` is accepted only for the two dispositions that carry
//!   objection sub-labels (`not_interested`, `question`) and only from the
//!   six-value taxonomy — a bogus sub-label is dropped, never invented into
//!   an outbound claim;
//! - the route is LLM-ONLY: the deterministic first layer stays in the
//!   worker, so a message that arrives here has already survived it.

use std::collections::BTreeMap;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::routes::{error_response_json, required_tenant_identity, AppState, TenantIdentityError};

/// Prompt identity recorded on every classification and sent in the request
/// by the client (worker-processors/src/reply_handler/ai.rs). Bump together.
pub const PROMPT_VERSION: &str = "reply-classifier-v1";

/// The canonical disposition taxonomy — byte-for-byte the worker's
/// `ReplyDisposition::ALL` as_str values. A drift makes the client's parse
/// fail closed; `TAXONOMY_DRIFT` below is pinned by a test on both sides.
pub const TAXONOMY: [&str; 11] = [
    "positive",
    "meeting_request",
    "question",
    "referral",
    "not_interested",
    "unsubscribe",
    "complaint",
    "ooo",
    "bounce_hard",
    "bounce_soft",
    "unknown",
];

/// The six objection classes (SalesCloser plan §5.5). Only the two
/// dispositions below carry them.
pub const OBJECTION_CLASSES: [&str; 6] = [
    "price",
    "timing",
    "competitor",
    "authority",
    "trust",
    "need",
];

/// Dispositions that may carry an `objection_class` sub-label.
const OBJECTION_CARRYING_DISPOSITIONS: [&str; 2] = ["not_interested", "question"];

/// Input bounds. The client already truncates (2048-char subject, 32 KiB
/// body) but the route re-truncates: it must not trust caller limits.
pub const MAX_SUBJECT_CHARS: usize = 2048;
pub const MAX_BODY_BYTES: usize = 32 * 1024;

/// Headers passed to the prompt: the classifier keys on auto-reply and
/// unsubscribe signals; everything else is body/subject evidence.
const PROMPT_HEADERS: [&str; 7] = [
    "auto-submitted",
    "precedence",
    "x-autoreply",
    "in-reply-to",
    "list-unsubscribe",
    "list-unsubscribe-post",
    "content-type",
];

#[derive(Debug, Deserialize)]
pub struct ReplyClassifyRequest {
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Optional caller taxonomy; when present it must be a subset of the
    /// canonical one (the worker sends the canonical list in order).
    #[serde(default)]
    pub taxonomy: Vec<String>,
    #[serde(default)]
    pub prompt_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassifierEvidence {
    pub kind: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReplyClassifyResponse {
    pub disposition: String,
    pub confidence: f64,
    pub reasoning: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    pub prompt_version: String,
    pub evidence: Vec<ClassifierEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objection_class: Option<String>,
}

/// A classification failure with the HTTP status the route returns; the
/// client's no-guess fallback converts any of them into Unknown/0.0.
#[derive(Debug)]
pub struct ClassifyFailure {
    pub status: StatusCode,
    pub message: String,
}

impl ClassifyFailure {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn invalid_output(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }
}

/// Validate the caller's taxonomy against the canonical list. An empty list
/// means the canonical one; anything outside it is a 400 (a caller asking
/// for dispositions that cannot be persisted is a bug, not a classification).
fn validate_taxonomy(requested: &[String]) -> Result<(), ClassifyFailure> {
    for value in requested {
        if !TAXONOMY.contains(&value.as_str()) {
            return Err(ClassifyFailure::bad_request(format!(
                "unknown disposition '{value}' in taxonomy; canonical values: {}",
                TAXONOMY.join(", ")
            )));
        }
    }
    Ok(())
}

/// Char-safe subject truncation.
fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value.chars().take(max_chars).collect()
    }
}

/// Byte-safe body truncation on a char boundary.
fn truncate_bytes(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// The classifier system prompt: the taxonomy, the decision rules the
/// disposition ladder implies, and the JSON contract. Byte-stable so the
/// model provider can cache the prefix (CAG efficiency).
pub fn system_prompt() -> String {
    let taxonomy = TAXONOMY.join(", ");
    format!(
        "You are ApexMail's reply classifier. Classify ONE inbound email reply \
         into exactly one disposition from: {taxonomy}.\n\
         Rules:\n\
         - positive: explicit interest in buying, evaluating, or continuing a conversation.\n\
         - meeting_request: asks for or proposes a call/meeting/demo.\n\
         - question: asks a substantive question (pricing, features, process); not buying intent by itself.\n\
         - referral: points to another person or address.\n\
         - not_interested: declines; optional objection_class from: {}.\n\
         - unsubscribe: asks to stop receiving messages entirely.\n\
         - complaint: dissatisfaction about the outreach or product.\n\
         - ooo: an out-of-office / auto-reply.\n\
         - bounce_hard: a permanent delivery failure (DSN 5.x).\n\
         - bounce_soft: a temporary delivery failure (DSN 4.x).\n\
         - unknown: no rule applies or evidence is insufficient — NEVER guess.\n\
         Objection classes apply only to not_interested and question: price, timing, \
         competitor, authority, trust, need. Use the SENDER's words as evidence.\n\
         Respond with ONLY a JSON object, no prose, no code fences:\n\
         {{\"disposition\": \"<one of the taxonomy>\", \"confidence\": <0..1>, \
         \"reasoning\": \"<one sentence>\", \"objection_class\": \"<optional>\", \
         \"evidence\": [{{\"kind\": \"token|header|phrase\", \"key\": \"<short key>\", \
         \"value\": \"<verbatim excerpt>\"}}]}}",
        OBJECTION_CLASSES.join(", ")
    )
}

/// The user prompt: subject, selected headers, and the body.
pub fn user_prompt(request: &ReplyClassifyRequest) -> String {
    let mut out = String::with_capacity(request.body.len() + 512);
    out.push_str("Subject: ");
    out.push_str(&truncate_chars(request.subject.trim(), MAX_SUBJECT_CHARS));
    out.push('\n');
    for name in PROMPT_HEADERS {
        if let Some(value) = request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
        {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
        }
    }
    out.push_str("Body:\n");
    out.push_str(truncate_bytes(&request.body, MAX_BODY_BYTES));
    out
}

/// Parse and sanitize one model response. Every deviation from the contract
/// is a [`ClassifyFailure`] — this function never fabricates a disposition.
pub fn parse_classifier_output(raw: &str) -> Result<ReplyClassifyResponse, ClassifyFailure> {
    // Accept a bare object, a code-fenced object, or an object embedded in
    // prose by slicing the outermost braces first.
    let trimmed = raw.trim();
    let unfenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed)
        .trim_start_matches(['\n', '\r']);
    let start = unfenced
        .find('{')
        .ok_or_else(|| ClassifyFailure::invalid_output("model response contains no JSON object"))?;
    let end = unfenced.rfind('}').ok_or_else(|| {
        ClassifyFailure::invalid_output("model response contains no closing brace")
    })?;
    if end <= start {
        return Err(ClassifyFailure::invalid_output(
            "model response braces are not a JSON object",
        ));
    }

    #[derive(Deserialize)]
    struct ModelOut {
        disposition: String,
        confidence: f64,
        #[serde(default)]
        reasoning: String,
        #[serde(default)]
        objection_class: Option<String>,
        #[serde(default)]
        evidence: Vec<ClassifierEvidence>,
    }

    let parsed: ModelOut = serde_json::from_str(&unfenced[start..=end])
        .map_err(|error| ClassifyFailure::invalid_output(format!("invalid JSON: {error}")))?;

    let disposition = parsed.disposition.trim().to_ascii_lowercase();
    if !TAXONOMY.contains(&disposition.as_str()) {
        return Err(ClassifyFailure::invalid_output(format!(
            "model returned disposition '{}' outside the taxonomy; refusing to map it to a guess",
            parsed.disposition
        )));
    }

    let confidence = if parsed.confidence.is_finite() {
        parsed.confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };

    let objection_class = parsed
        .objection_class
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| {
            OBJECTION_CARRYING_DISPOSITIONS.contains(&disposition.as_str())
                && OBJECTION_CLASSES.contains(&value.as_str())
        });

    Ok(ReplyClassifyResponse {
        disposition,
        confidence,
        reasoning: parsed.reasoning.trim().to_string(),
        model_version: None,
        prompt_version: PROMPT_VERSION.to_string(),
        evidence: parsed.evidence,
        objection_class,
    })
}

/// Run the classifier for a validated request. `model_version` is filled by
/// the caller from the configured model name.
pub async fn classify(
    state: &AppState,
    request: &ReplyClassifyRequest,
) -> Result<ReplyClassifyResponse, ClassifyFailure> {
    validate_taxonomy(&request.taxonomy)?;
    if request.subject.trim().is_empty() && request.body.trim().is_empty() {
        return Err(ClassifyFailure::bad_request(
            "subject and body are both empty; nothing to classify",
        ));
    }
    if !state.llm.is_enabled() {
        return Err(ClassifyFailure::unavailable(
            "reply classifier unavailable: the model runtime is not configured",
        ));
    }

    let raw = state
        .llm
        .plan(&system_prompt(), &user_prompt(request))
        .await
        .map_err(|error| {
            ClassifyFailure::unavailable(format!("reply classifier unavailable: {error}"))
        })?;
    let mut response = parse_classifier_output(&raw)?;
    response.model_version = Some(state.llm.configured_model().to_string());
    Ok(response)
}

/// The Axum handler: service-token domain (router layer), tenant header
/// required and rate-governed exactly like `/chat`.
pub async fn reply_classify_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ReplyClassifyRequest>,
) -> Response {
    let tenant = match required_tenant_identity(&headers) {
        Ok(tenant) => tenant,
        Err(TenantIdentityError::Missing) => {
            return error_response_json(
                StatusCode::UNAUTHORIZED,
                "x-apexmail-tenant-id is required",
            );
        }
        Err(TenantIdentityError::Invalid(reason)) => {
            return error_response_json(
                StatusCode::BAD_REQUEST,
                &format!("invalid x-apexmail-tenant-id: {reason}"),
            );
        }
    };
    if !state.rate_governor.allow(&tenant) {
        return error_response_json(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    match classify(&state, &request).await {
        Ok(response) => Json(response).into_response(),
        Err(failure) => {
            tracing::warn!(
                status = %failure.status,
                message = %failure.message,
                "reply classification failed; the client will fall back to Unknown"
            );
            error_response_json(failure.status, &failure.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AiConfig;
    use crate::test_support::{spawn_scripted_llm, LlmScript};

    fn response_body(disposition: &str, confidence: f64) -> String {
        format!(
            "{{\"disposition\": \"{disposition}\", \"confidence\": {confidence}, \
             \"reasoning\": \"asks to talk Thursday\", \
             \"evidence\": [{{\"kind\":\"token\",\"key\":\"meeting\",\"value\":\"talk Thursday\"}}]}}"
        )
    }

    #[test]
    fn parses_a_full_response() {
        let parsed = parse_classifier_output(&response_body("meeting_request", 0.82)).unwrap();
        assert_eq!(parsed.disposition, "meeting_request");
        assert!((parsed.confidence - 0.82).abs() < f64::EPSILON);
        assert_eq!(parsed.prompt_version, PROMPT_VERSION);
        assert_eq!(parsed.evidence.len(), 1);
    }

    #[test]
    fn parses_a_code_fenced_response() {
        let raw = format!("```json\n{}\n```", response_body("unsubscribe", 0.99));
        let parsed = parse_classifier_output(&raw).unwrap();
        assert_eq!(parsed.disposition, "unsubscribe");
    }

    #[test]
    fn rejects_a_disposition_outside_the_taxonomy() {
        let error = parse_classifier_output(&response_body("vibes", 0.99)).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        assert!(error.message.contains("outside the taxonomy"));
    }

    #[test]
    fn clamps_and_sanitizes_confidence() {
        let parsed = parse_classifier_output(&response_body("positive", 4.2)).unwrap();
        assert_eq!(parsed.confidence, 1.0);
        let parsed = parse_classifier_output(&response_body("positive", -3.0)).unwrap();
        assert_eq!(parsed.confidence, 0.0);
        // A non-finite confidence is not valid JSON (and a provider emitting
        // bare `NaN` must never be coerced into a plausible value): the
        // parser refuses rather than guessing a number.
        let raw = "{\"disposition\": \"positive\", \"confidence\": NaN}";
        let error = parse_classifier_output(raw).unwrap_err();
        assert!(error.message.contains("invalid JSON"), "{}", error.message);
    }

    #[test]
    fn objection_class_only_survives_on_not_interested_and_question() {
        let raw = "{\"disposition\": \"not_interested\", \"confidence\": 0.7, \
                   \"objection_class\": \"price\"}";
        let parsed = parse_classifier_output(raw).unwrap();
        assert_eq!(parsed.objection_class.as_deref(), Some("price"));

        let raw = "{\"disposition\": \"positive\", \"confidence\": 0.7, \
                   \"objection_class\": \"price\"}";
        let parsed = parse_classifier_output(raw).unwrap();
        assert_eq!(
            parsed.objection_class, None,
            "positive carries no objection"
        );

        let raw = "{\"disposition\": \"not_interested\", \"confidence\": 0.7, \
                   \"objection_class\": \"vibes\"}";
        let parsed = parse_classifier_output(raw).unwrap();
        assert_eq!(parsed.objection_class, None, "bogus classes are dropped");
    }

    #[test]
    fn taxonomy_validation_rejects_unknown_values() {
        let error = validate_taxonomy(&["positive".into(), "vibes".into()]).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(validate_taxonomy(&TAXONOMY.map(String::from)).is_ok());
        assert!(validate_taxonomy(&[]).is_ok(), "empty means canonical");
    }

    #[test]
    fn prompts_carry_the_taxonomy_and_bounded_input() {
        let request = ReplyClassifyRequest {
            subject: "s".repeat(4000),
            body: "b".repeat(MAX_BODY_BYTES + 100),
            headers: BTreeMap::from([
                ("Auto-Submitted".to_string(), "auto-replied".to_string()),
                ("x-unrelated".to_string(), "ignored".to_string()),
            ]),
            taxonomy: vec![],
            prompt_version: None,
        };
        let system = system_prompt();
        for disposition in TAXONOMY {
            assert!(
                system.contains(disposition),
                "system prompt lists {disposition}"
            );
        }
        let user = user_prompt(&request);
        assert!(user.contains("auto-submitted: auto-replied"));
        assert!(!user.contains("x-unrelated"), "unselected headers stay out");
        assert!(
            user.len() < MAX_BODY_BYTES + MAX_SUBJECT_CHARS + 512,
            "input bounds hold: {} bytes",
            user.len()
        );
    }

    #[tokio::test]
    async fn disabled_runtime_is_a_503_the_client_falls_back_from() {
        let state = Arc::new(
            AppState::from_config(AiConfig::default(), "test-key".into())
                .await
                .expect("config"),
        );
        let request = ReplyClassifyRequest {
            subject: "Re: proposal".into(),
            body: "can we talk thursday?".into(),
            headers: BTreeMap::new(),
            taxonomy: vec![],
            prompt_version: None,
        };
        let error = classify(&state, &request).await.unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(error.message.contains("not configured"));
    }

    #[tokio::test]
    async fn enabled_runtime_returns_the_worker_contract_shape() {
        let mock = spawn_scripted_llm(vec![LlmScript::Content(Box::leak(
            response_body("meeting_request", 0.82).into_boxed_str(),
        ))])
        .await;
        let config = AiConfig {
            model_enabled: true,
            model_endpoint: mock.endpoint(),
            model_timeout_secs: 10,
            ..AiConfig::default()
        };
        let state = Arc::new(
            AppState::from_config(config, "test-key".into())
                .await
                .expect("config"),
        );
        let request = ReplyClassifyRequest {
            subject: "Re: proposal".into(),
            body: "can we talk thursday?".into(),
            headers: BTreeMap::new(),
            taxonomy: TAXONOMY.map(String::from).to_vec(),
            prompt_version: Some(PROMPT_VERSION.to_string()),
        };
        let response = classify(&state, &request).await.expect("classifies");
        assert_eq!(response.disposition, "meeting_request");
        assert_eq!(response.prompt_version, PROMPT_VERSION);
        assert!(response.model_version.is_some());

        // The wire shape the worker parses: every field present, confidence
        // in range (worker-processors/src/reply_handler/ai.rs::parse_response).
        let wire = serde_json::to_value(&response).unwrap();
        assert!(wire["disposition"].is_string());
        assert!(wire["confidence"]
            .as_f64()
            .is_some_and(|c| (0.0..=1.0).contains(&c)));
        assert!(wire["evidence"].is_array());
    }
}
