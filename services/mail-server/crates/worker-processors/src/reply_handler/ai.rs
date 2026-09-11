//! Semantic reply classification — layer 2 of 3.
//!
//! Everything the deterministic layer ([`super::deterministic`]) could not
//! prove is decided here. The layer is provider-agnostic: it defines the
//! [`ReplyClassifier`] trait, one HTTP implementation that talks to the
//! ApexMail AI service over a documented JSON contract, and a static fallback
//! used when no AI is configured or the call fails.
//!
//! # No hallucination on outage (release gate)
//!
//! An AI outage is a configuration/operations failure, not a licence to
//! guess. When the AI is unconfigured or errors, [`classify_or_fallback`]
//! returns `Unknown` with `confidence: 0.0` and a reason naming the outage.
//! It never fabricates a positive/negative category, which in turn makes the
//! policy layer stop the next outbound touch pending classification.
//!
//! # HTTP contract (vendor-neutral)
//!
//! `POST <base>/reply/classify` (or exactly `<base>` when the configured
//! endpoint already names the classify path), `Content-Type: application/json`,
//! optional `x-api-key`:
//!
//! ```json
//! {
//!   "subject": "Re: proposal",
//!   "body": "can we talk Thursday?",
//!   "headers": { "auto-submitted": "no" },
//!   "taxonomy": ["positive", "meeting_request", "question", "referral",
//!                "not_interested", "unsubscribe", "complaint", "ooo",
//!                "bounce_hard", "bounce_soft", "unknown"],
//!   "prompt_version": "reply-classifier-v1"
//! }
//! ```
//!
//! Response (either bare or wrapped in `{"data": ...}`):
//!
//! ```json
//! {
//!   "disposition": "meeting_request",
//!   "confidence": 0.82,
//!   "reasoning": "asks to talk Thursday",
//!   "model_version": "apexmail-reply-2026-09",
//!   "prompt_version": "reply-classifier-v1",
//!   "evidence": [{"kind": "token", "key": "meeting", "value": "talk Thursday"}]
//! }
//! ```
//!
//! Any deviation (non-2xx, malformed JSON, unknown disposition) is an error;
//! the caller's fallback turns it into the audited Unknown result.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroizing;

use super::deterministic::truncate_utf8;
use super::types::{AiClassification, Evidence, ReplyDisposition, ReplyInput};
use crate::common::ReplyHandlerConfig;

/// Prompt identity recorded on every AI classification and sent with the
/// request. Bump when the prompt/contract changes.
pub const AI_PROMPT_VERSION: &str = "reply-classifier-v1";

/// Prefix of the reasoning recorded when the AI layer is unavailable. Tests
/// and operators key on it; keep it stable.
pub const AI_OUTAGE_REASON_PREFIX: &str = "ai classifier outage";

/// Hard cap for the text sent to the AI service. A hostile 1 MB body must not
/// become a 1 MB outbound request.
pub const MAX_AI_INPUT_BYTES: usize = 32 * 1024;

/// Failure modes of a [`ReplyClassifier`]. Every variant is recoverable by
/// falling back to the conservative Unknown result; none of them may be
/// swallowed into a guessed category.
#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error("ai classifier is not configured")]
    NotConfigured,
    #[error("ai classifier transport failure: {0}")]
    Transport(String),
    #[error("ai classifier returned HTTP {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("ai classifier returned an invalid response: {0}")]
    InvalidResponse(String),
}

/// The provider-agnostic semantic classifier contract.
#[async_trait]
pub trait ReplyClassifier: Send + Sync {
    /// Classify one inbound message.
    async fn classify(&self, input: &ReplyInput) -> Result<AiClassification, ClassifyError>;

    /// Stable name for logs and the persisted `model_version` fallback.
    fn name(&self) -> &'static str {
        "reply-classifier"
    }
}

/// The deterministic fallback used when no AI is configured: it is
/// deliberately incapable of guessing. It returns Unknown/0.0 with a reason
/// that names the missing configuration.
#[derive(Debug, Default)]
pub struct StaticFallbackClassifier;

#[async_trait]
impl ReplyClassifier for StaticFallbackClassifier {
    async fn classify(&self, _input: &ReplyInput) -> Result<AiClassification, ClassifyError> {
        Ok(AiClassification::unknown_outage(format!(
            "{AI_OUTAGE_REASON_PREFIX}: no ai classifier is configured; \
             deterministic parsing found nothing provable — refusing to guess"
        )))
    }

    fn name(&self) -> &'static str {
        "static_fallback"
    }
}

/// Run a classifier and convert ANY failure (or an implausible response) into
/// the conservative Unknown/0.0 outage result. This is the only function the
/// processor uses, so "AI failure never hallucinates" holds by construction.
pub async fn classify_or_fallback(
    classifier: &dyn ReplyClassifier,
    input: &ReplyInput,
) -> AiClassification {
    match classifier.classify(input).await {
        Ok(classification) => sanitize_classification(classification),
        Err(error) => {
            warn!(
                classifier = classifier.name(),
                %error,
                "AI reply classification unavailable; falling back to Unknown (no guess)"
            );
            AiClassification::unknown_outage(format!(
                "{AI_OUTAGE_REASON_PREFIX}: {}; refusing to guess a category",
                error
            ))
        }
    }
}

/// Clamp implausible model output into the canonical value domain. A model
/// that returns NaN/out-of-range confidence must not bypass the policy
/// threshold by accident.
fn sanitize_classification(mut classification: AiClassification) -> AiClassification {
    if !classification.confidence.is_finite() {
        classification.confidence = 0.0;
    } else {
        classification.confidence = classification.confidence.clamp(0.0, 1.0);
    }
    classification
}

/// HTTP implementation against the ApexMail AI service.
///
/// There is no vendor SDK here and no vendor-specific request shape: any
/// service implementing the documented contract works.
pub struct HttpReplyClassifier {
    client: Client,
    classify_url: String,
    api_key: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for HttpReplyClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpReplyClassifier")
            .field("classify_url", &self.classify_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Serialize)]
struct ClassifyRequest<'a> {
    subject: &'a str,
    body: &'a str,
    headers: &'a std::collections::BTreeMap<String, String>,
    taxonomy: Vec<&'static str>,
    prompt_version: &'static str,
}

impl HttpReplyClassifier {
    /// Build a classifier for the AI service at `base_url`.
    ///
    /// `base_url` may be either a service base URL (the `/reply/classify`
    /// path is appended) or the full classify endpoint.
    pub fn new(
        base_url: &str,
        api_key: Option<Zeroizing<String>>,
        timeout: Duration,
    ) -> Result<Self, ClassifyError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(ClassifyError::NotConfigured);
        }
        let classify_url = if trimmed.ends_with("/reply/classify") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/reply/classify")
        };
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ClassifyError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            classify_url,
            api_key,
        })
    }

    /// Parse one response body. Public so the contract is unit-testable
    /// without a live service.
    pub fn parse_response(value: &serde_json::Value) -> Result<AiClassification, ClassifyError> {
        // Accept both bare and `{"data": ...}` envelopes.
        let payload = value.get("data").unwrap_or(value);

        let disposition_raw = payload
            .get("disposition")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                ClassifyError::InvalidResponse("missing string 'disposition'".to_string())
            })?;
        let disposition: ReplyDisposition = disposition_raw.parse().map_err(|error: String| {
            ClassifyError::InvalidResponse(format!("{error}; refusing to map it to a guess"))
        })?;
        let confidence = payload
            .get("confidence")
            .and_then(|value| value.as_f64())
            .ok_or_else(|| {
                ClassifyError::InvalidResponse("missing numeric 'confidence'".to_string())
            })?;
        let reasoning = payload
            .get("reasoning")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let model_version = payload
            .get("model_version")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        let prompt_version = payload
            .get("prompt_version")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        let evidence = payload
            .get("evidence")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let kind = item.get("kind")?.as_str()?;
                        let key = item.get("key")?.as_str()?;
                        let value = item.get("value")?.as_str()?;
                        Some(Evidence::new(kind, key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(sanitize_classification(AiClassification {
            disposition,
            confidence,
            reasoning,
            model_version,
            prompt_version,
            evidence,
        }))
    }
}

#[async_trait]
impl ReplyClassifier for HttpReplyClassifier {
    async fn classify(&self, input: &ReplyInput) -> Result<AiClassification, ClassifyError> {
        let request = ClassifyRequest {
            subject: truncate_utf8(&input.subject, 2048),
            body: truncate_utf8(&input.body, MAX_AI_INPUT_BYTES),
            headers: &input.headers,
            taxonomy: ReplyDisposition::ALL.iter().map(|d| d.as_str()).collect(),
            prompt_version: AI_PROMPT_VERSION,
        };

        let mut builder = self.client.post(&self.classify_url).json(&request);
        if let Some(key) = self.api_key.as_deref() {
            builder = builder.header("x-api-key", key);
        }

        let response = builder
            .send()
            .await
            .map_err(|error| ClassifyError::Transport(error.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = truncate_utf8(&response.text().await.unwrap_or_default(), 2048).to_string();
            return Err(ClassifyError::Upstream {
                status: status.as_u16(),
                body,
            });
        }

        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|error| ClassifyError::InvalidResponse(error.to_string()))?;
        Self::parse_response(&value)
    }

    fn name(&self) -> &'static str {
        "apexmail_ai_http"
    }
}

/// Build the process-wide classifier from configuration: the HTTP classifier
/// when the AI service is explicitly enabled and its base URL is set, the
/// static fallback (never guessing) otherwise.
pub fn classifier_from_config(config: &ReplyHandlerConfig) -> Arc<dyn ReplyClassifier> {
    if config.llm_enabled {
        match config.llm_endpoint.as_deref() {
            Some(endpoint) => {
                match HttpReplyClassifier::new(
                    endpoint,
                    config.llm_api_key.clone(),
                    Duration::from_secs(15),
                ) {
                    Ok(classifier) => return Arc::new(classifier),
                    Err(error) => warn!(
                        %error,
                        "LLM enabled but endpoint is unusable; using the static fallback"
                    ),
                }
            }
            None => warn!(
                "LLM enabled but no endpoint configured; using the static fallback \
                 (classifications will be Unknown, never guessed)"
            ),
        }
    }
    Arc::new(StaticFallbackClassifier)
}

/// Serializable shape reused by tests and logging.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClassifyResponseWire {
    pub disposition: String,
    pub confidence: f64,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub model_version: Option<String>,
    #[serde(default)]
    pub prompt_version: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A classifier that always errors — the outage case.
    struct ErroringClassifier;
    #[async_trait]
    impl ReplyClassifier for ErroringClassifier {
        async fn classify(&self, _input: &ReplyInput) -> Result<AiClassification, ClassifyError> {
            Err(ClassifyError::Transport("connection refused".to_string()))
        }
        fn name(&self) -> &'static str {
            "erroring"
        }
    }

    /// A classifier that always returns the naive guess — used to prove the
    /// fallback is what protects positive categories.
    struct NaivelyPositiveClassifier;
    #[async_trait]
    impl ReplyClassifier for NaivelyPositiveClassifier {
        async fn classify(&self, _input: &ReplyInput) -> Result<AiClassification, ClassifyError> {
            Ok(AiClassification {
                disposition: ReplyDisposition::Positive,
                confidence: 0.9,
                reasoning: "looks positive".into(),
                model_version: None,
                prompt_version: None,
                evidence: vec![],
            })
        }
    }

    // ── Outage does not hallucinate (release gate) ───────────────────

    #[tokio::test]
    async fn ai_error_returns_unknown_zero_confidence_with_outage_reason() {
        let result = classify_or_fallback(&ErroringClassifier, &ReplyInput::new("", "")).await;
        assert_eq!(result.disposition, ReplyDisposition::Unknown);
        assert_eq!(result.confidence, 0.0);
        assert!(
            result
                .reasoning
                .to_lowercase()
                .contains("ai classifier outage"),
            "reason must name the outage: {}",
            result.reasoning
        );
        assert!(
            !result.is_positive_category(),
            "an outage must never produce a positive category"
        );
    }

    #[tokio::test]
    async fn ai_error_on_vaguely_positive_body_never_guesses() {
        // The naive thing to do would be to read "thanks, sounds interesting"
        // as Positive. With the AI down there is no verified interpretation.
        let input = ReplyInput::new(
            "Re: your proposal",
            "Thanks — sounds interesting, maybe we should talk sometime?",
        );
        let result = classify_or_fallback(&ErroringClassifier, &input).await;
        assert_eq!(result.disposition, ReplyDisposition::Unknown);
        assert_eq!(result.confidence, 0.0);
        assert!(!result.is_positive_category());
        assert_ne!(result.disposition, ReplyDisposition::Positive);
    }

    #[tokio::test]
    async fn unconfigured_ai_returns_unknown_not_a_guess() {
        let result = classify_or_fallback(
            &StaticFallbackClassifier,
            &ReplyInput::new("Re: hi", "sounds good, let's do it"),
        )
        .await;
        assert_eq!(result.disposition, ReplyDisposition::Unknown);
        assert_eq!(result.confidence, 0.0);
        assert!(result.reasoning.contains(AI_OUTAGE_REASON_PREFIX));
    }

    // ── The classifier contract is honored when healthy ──────────────

    #[tokio::test]
    async fn healthy_ai_result_passes_through() {
        let result =
            classify_or_fallback(&NaivelyPositiveClassifier, &ReplyInput::new("Re: hi", "")).await;
        assert_eq!(result.disposition, ReplyDisposition::Positive);
        assert!(result.is_positive_category());
    }

    #[tokio::test]
    async fn nan_confidence_is_sanitized_to_zero() {
        struct NanClassifier;
        #[async_trait]
        impl ReplyClassifier for NanClassifier {
            async fn classify(
                &self,
                _input: &ReplyInput,
            ) -> Result<AiClassification, ClassifyError> {
                Ok(AiClassification {
                    disposition: ReplyDisposition::Positive,
                    confidence: f64::NAN,
                    reasoning: String::new(),
                    model_version: None,
                    prompt_version: None,
                    evidence: vec![],
                })
            }
        }
        let result = classify_or_fallback(&NanClassifier, &ReplyInput::new("", "")).await;
        assert_eq!(result.confidence, 0.0);
        assert!(result.confidence.is_finite());
    }

    // ── Response parsing ─────────────────────────────────────────────

    #[test]
    fn parses_a_full_response() {
        let value = serde_json::json!({
            "disposition": "meeting_request",
            "confidence": 0.82,
            "reasoning": "asks to talk Thursday",
            "model_version": "apexmail-reply-2026-09",
            "prompt_version": "reply-classifier-v1",
            "evidence": [{"kind": "token", "key": "meeting", "value": "talk Thursday"}]
        });
        let parsed = HttpReplyClassifier::parse_response(&value).unwrap();
        assert_eq!(parsed.disposition, ReplyDisposition::MeetingRequest);
        assert!((parsed.confidence - 0.82).abs() < f64::EPSILON);
        assert_eq!(parsed.evidence.len(), 1);
        assert_eq!(
            parsed.model_version.as_deref(),
            Some("apexmail-reply-2026-09")
        );
        assert_eq!(
            parsed.prompt_version.as_deref(),
            Some("reply-classifier-v1")
        );
    }

    #[test]
    fn parses_a_data_envelope() {
        let value = serde_json::json!({
            "data": {"disposition": "unsubscribe", "confidence": 0.99, "reasoning": "asked"}
        });
        let parsed = HttpReplyClassifier::parse_response(&value).unwrap();
        assert_eq!(parsed.disposition, ReplyDisposition::Unsubscribe);
    }

    #[test]
    fn unknown_disposition_string_is_an_error_not_a_guess() {
        let value = serde_json::json!({"disposition": "vibes", "confidence": 0.99});
        let error = HttpReplyClassifier::parse_response(&value).unwrap_err();
        assert!(matches!(error, ClassifyError::InvalidResponse(_)));
    }

    #[test]
    fn missing_confidence_is_an_error() {
        let value = serde_json::json!({"disposition": "positive"});
        assert!(HttpReplyClassifier::parse_response(&value).is_err());
    }

    #[test]
    fn out_of_range_confidence_is_clamped() {
        let value = serde_json::json!({"disposition": "positive", "confidence": 7.5});
        let parsed = HttpReplyClassifier::parse_response(&value).unwrap();
        assert_eq!(parsed.confidence, 1.0);
    }

    #[test]
    fn empty_base_url_is_not_configured() {
        let error = HttpReplyClassifier::new("  ", None, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(error, ClassifyError::NotConfigured));
    }

    #[test]
    fn full_classify_path_is_not_doubled() {
        let classifier = HttpReplyClassifier::new(
            "http://ai:3012/reply/classify",
            None,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(classifier.classify_url, "http://ai:3012/reply/classify");
        let classifier =
            HttpReplyClassifier::new("http://ai:3012/", None, Duration::from_secs(1)).unwrap();
        assert_eq!(classifier.classify_url, "http://ai:3012/reply/classify");
    }

    #[tokio::test]
    async fn unreachable_service_errors_instead_of_panicking() {
        // Port 1 on localhost is refused immediately; no network dependency.
        let classifier =
            HttpReplyClassifier::new("http://127.0.0.1:1", None, Duration::from_millis(250))
                .unwrap();
        let error = classifier
            .classify(&ReplyInput::new("Re: hi", "hello"))
            .await
            .unwrap_err();
        assert!(matches!(error, ClassifyError::Transport(_)));
    }

    #[test]
    fn config_without_llm_yields_the_static_fallback() {
        let config = ReplyHandlerConfig::default();
        assert!(!config.llm_enabled);
        let classifier = classifier_from_config(&config);
        assert_eq!(classifier.name(), "static_fallback");
    }

    #[test]
    fn config_with_llm_and_endpoint_yields_http() {
        let config = ReplyHandlerConfig {
            llm_enabled: true,
            llm_endpoint: Some("http://ai:3012".to_string()),
            ..ReplyHandlerConfig::default()
        };
        let classifier = classifier_from_config(&config);
        assert_eq!(classifier.name(), "apexmail_ai_http");
    }

    #[test]
    fn config_with_llm_but_no_endpoint_yields_fallback() {
        let config = ReplyHandlerConfig {
            llm_enabled: true,
            llm_endpoint: None,
            ..ReplyHandlerConfig::default()
        };
        assert_eq!(classifier_from_config(&config).name(), "static_fallback");
    }

    #[test]
    fn ai_input_is_bounded() {
        let body = "z".repeat(MAX_AI_INPUT_BYTES * 4);
        let truncated = truncate_utf8(&body, MAX_AI_INPUT_BYTES);
        assert!(truncated.len() <= MAX_AI_INPUT_BYTES);
    }
}
