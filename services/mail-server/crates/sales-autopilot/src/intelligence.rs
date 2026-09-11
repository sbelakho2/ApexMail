//! §12 — evidence-grounded, provider-agnostic sales intelligence.
//!
//! The engine talks to an AI service through one trait, [`SalesIntelligence`],
//! so the deployment can replace the provider without touching the sales
//! pipeline. Two implementations ship here:
//!
//! * [`HttpSalesIntelligence`] — the ApexMail AI service over HTTP, following
//!   the same base-URL/api-key pattern as the enrichment HTTP provider
//!   (`crates/sales-autopilot/src/enrichment/providers/http.rs`), reading
//!   `APEXMAIL_AI_BASE_URL` / `SALES_AI_BASE_URL` and
//!   `APEXMAIL_AI_API_KEY` / `SALES_AI_API_KEY` from the environment (read
//!   here rather than in `config.rs`, which this workstream must not edit);
//! * [`OfflineIntelligence`] — deterministic, no network. Used when no AI is
//!   configured, which keeps the service working without AI and makes every
//!   call testable.
//!
//! # The hard rule (§12)
//!
//! **Every AI-generated factual statement must either reference at least one
//! `evidence_id`, or be classified as a hypothesis. If neither is possible,
//! omit it.**
//!
//! [`validate_claims`] is that rule as a pure function: it takes AI output and
//! the set of `evidence_id`s the caller is willing to stand behind, and
//! returns the surviving claims plus every omitted claim with a reason. A
//! citation to an id outside the allowed set is omitted — a **hallucinated
//! citation is worse than no citation**, because it launders an invention as
//! provenance.
//!
//! # The outage rule (§26)
//!
//! When AI is unavailable the system falls back to verified static content,
//! never to hallucination. [`OfflineIntelligence`] exists precisely so this
//! path is explicit and tested: research produces zero new evidence rows and
//! says why (see [`crate::research`]); drafting uses a static template that
//! asserts nothing it was not given.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::experiments::NextActionInput;
use crate::types::{DecisionAction, ReplyDisposition};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Intelligence-layer failures. `NotConfigured`/`Unavailable` are the outage
/// signals the caller must handle by falling back, never by inventing data.
#[derive(Debug, thiserror::Error)]
pub enum IntelligenceError {
    #[error("AI service is not configured: {0}")]
    NotConfigured(String),
    #[error("AI service unavailable: {0}")]
    Unavailable(String),
    #[error("AI service returned an invalid response: {0}")]
    InvalidResponse(String),
    #[error("AI output rejected: {0}")]
    Rejected(String),
}

impl IntelligenceError {
    /// Is this an outage (as opposed to a successfully parsed but
    /// low-quality response)? Outages trigger the static fallback.
    pub fn is_outage(&self) -> bool {
        matches!(self, Self::NotConfigured(_) | Self::Unavailable(_))
    }
}

// ---------------------------------------------------------------------------
// Request/response shapes
// ---------------------------------------------------------------------------

/// A grounded proposition the caller already trusts, passed to the AI so it
/// can cite it by id instead of restating it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBrief {
    pub evidence_id: Uuid,
    pub proposition: String,
    pub confidence: f64,
    pub source_kind: String,
}

/// Account research request.
#[derive(Debug, Clone)]
pub struct ResearchRequest<'a> {
    pub tenant_id: &'a str,
    pub account_id: Option<Uuid>,
    pub domain: &'a str,
    pub company: Option<&'a str>,
    pub country: Option<&'a str>,
    pub industry: Option<&'a str>,
    /// The evidence set the AI is allowed to cite (and the only ids that
    /// survive [`validate_claims`]).
    pub evidence: &'a [EvidenceBrief],
}

/// One claim from the AI. `evidence_id` must be one of the allowed ids unless
/// `is_hypothesis` is set (then the claim is labelled instead of grounded).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchClaim {
    pub proposition: String,
    pub confidence: f64,
    #[serde(default)]
    pub source_kind: Option<String>,
    #[serde(default)]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub evidence_id: Option<Uuid>,
    #[serde(default)]
    pub is_hypothesis: bool,
}

/// Research findings. `fallback` names the static/offline path when the AI was
/// not used, so the caller can log why nothing new was written.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResearchFindings {
    #[serde(default)]
    pub claims: Vec<ResearchClaim>,
    #[serde(default)]
    pub model_version: Option<String>,
    #[serde(default)]
    pub fallback: Option<String>,
}

/// Angle selection request.
#[derive(Debug, Clone)]
pub struct AngleRequest<'a> {
    pub tenant_id: &'a str,
    pub account_id: Option<Uuid>,
    pub evidence_ids: &'a [Uuid],
    pub offer: Option<&'a str>,
    pub persona: Option<&'a str>,
    pub hypotheses: &'a [String],
}

/// The chosen messaging angle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AngleSelection {
    pub angle: String,
    pub rationale: String,
    #[serde(default)]
    pub cited_evidence_ids: Vec<Uuid>,
    #[serde(default)]
    pub hypothesis_based: bool,
}

/// Message draft request.
#[derive(Debug, Clone)]
pub struct DraftRequest<'a> {
    pub tenant_id: &'a str,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub offer: Option<&'a str>,
    pub angle: Option<&'a str>,
    pub evidence: &'a [EvidenceBrief],
    pub language: Option<&'a str>,
    pub sender_name: Option<&'a str>,
    pub company: Option<&'a str>,
    pub contact_name: Option<&'a str>,
}

/// A drafted message plus the claims it makes, so the caller can validate
/// every factual statement before it is sent.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DraftedMessage {
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub cited_evidence_ids: Vec<Uuid>,
    #[serde(default)]
    pub claims: Vec<ResearchClaim>,
    #[serde(default)]
    pub fallback: Option<String>,
}

/// Inbound reply classification request.
#[derive(Debug, Clone)]
pub struct ReplyRequest<'a> {
    pub tenant_id: &'a str,
    pub enrollment_id: Option<Uuid>,
    pub from: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
}

/// Canonical reply classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplyClassification {
    pub disposition: ReplyDisposition,
    pub confidence: f64,
    pub reasoning: String,
    #[serde(default)]
    pub suggested_action: Option<DecisionAction>,
}

/// Next-best-action request; the pure policy in
/// [`crate::experiments::next_best_action`] is the fallback and the ground
/// truth for the offline implementation.
#[derive(Debug, Clone)]
pub struct NextActionRequest<'a> {
    pub tenant_id: &'a str,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub input: &'a NextActionInput,
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// Provider-agnostic sales intelligence. Every method is fallible; an outage
/// is reported as [`IntelligenceError::Unavailable`] /
/// [`IntelligenceError::NotConfigured`] so callers can fall back to static
/// content instead of hallucinating.
#[async_trait::async_trait]
pub trait SalesIntelligence: Send + Sync + std::fmt::Debug {
    async fn research_account(
        &self,
        req: &ResearchRequest<'_>,
    ) -> Result<ResearchFindings, IntelligenceError>;

    async fn select_angle(
        &self,
        req: &AngleRequest<'_>,
    ) -> Result<AngleSelection, IntelligenceError>;

    async fn draft_message(
        &self,
        req: &DraftRequest<'_>,
    ) -> Result<DraftedMessage, IntelligenceError>;

    async fn classify_reply(
        &self,
        req: &ReplyRequest<'_>,
    ) -> Result<ReplyClassification, IntelligenceError>;

    async fn determine_next_action(
        &self,
        req: &NextActionRequest<'_>,
    ) -> Result<DecisionAction, IntelligenceError>;
}

/// The configured provider, or the deterministic offline implementation.
/// The sales pipeline never has to branch on configuration.
pub fn intelligence_from_env() -> Arc<dyn SalesIntelligence> {
    match HttpSalesIntelligence::from_env() {
        Some(http) => Arc::new(http),
        None => {
            tracing::warn!(
                "no AI service configured ({} / {}); using deterministic offline intelligence \
                 and verified static content only",
                AI_BASE_URL_ENV,
                AI_API_KEY_ENV
            );
            Arc::new(OfflineIntelligence::new())
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP implementation
// ---------------------------------------------------------------------------

/// Primary environment variable for the AI service base URL.
pub const AI_BASE_URL_ENV: &str = "APEXMAIL_AI_BASE_URL";
/// Alias accepted for the AI service base URL.
pub const AI_BASE_URL_ENV_ALT: &str = "SALES_AI_BASE_URL";
/// Primary environment variable for the AI service API key.
pub const AI_API_KEY_ENV: &str = "APEXMAIL_AI_API_KEY";
/// Alias accepted for the AI service API key.
pub const AI_API_KEY_ENV_ALT: &str = "SALES_AI_API_KEY";

/// Path of the research endpoint.
pub const RESEARCH_PATH: &str = "/v1/sales/research";
/// Path of the angle endpoint.
pub const ANGLE_PATH: &str = "/v1/sales/angle";
/// Path of the drafting endpoint.
pub const DRAFT_PATH: &str = "/v1/sales/draft";
/// Path of the reply-classification endpoint.
pub const REPLY_PATH: &str = "/v1/sales/classify-reply";
/// Path of the next-action endpoint.
pub const NEXT_ACTION_PATH: &str = "/v1/sales/next-action";

/// The ApexMail AI service over HTTP.
#[derive(Debug, Clone)]
pub struct HttpSalesIntelligence {
    base_url: String,
    api_key: String,
    model_version: String,
    client: reqwest::Client,
}

/// Read the first present, non-empty variable among `names`.
fn read_env(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

impl HttpSalesIntelligence {
    /// Construct with an explicit base URL and key.
    pub fn new(base_url: &str, api_key: &str) -> Self {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("ApexMail/1.0 (sales-intelligence)")
            .build()
        {
            Ok(client) => client,
            // A client-build failure (e.g. TLS backend unavailable) must not
            // panic the service; the default client is the degraded fallback.
            Err(_) => reqwest::Client::new(),
        };
        Self {
            base_url: base_url.trim().trim_end_matches('/').to_string(),
            api_key: api_key.trim().to_string(),
            model_version: "apexmail-ai".to_string(),
            client,
        }
    }

    /// Build from the environment; `None` when unconfigured, which selects the
    /// offline fallback.
    pub fn from_env() -> Option<Self> {
        let base_url = read_env(&[AI_BASE_URL_ENV, AI_BASE_URL_ENV_ALT])?;
        let api_key = read_env(&[AI_API_KEY_ENV, AI_API_KEY_ENV_ALT]).unwrap_or_default();
        Some(Self::new(&base_url, &api_key))
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn model_version(&self) -> &str {
        &self.model_version
    }

    async fn post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, IntelligenceError> {
        if self.base_url.is_empty() {
            return Err(IntelligenceError::NotConfigured(
                "base URL is empty".to_string(),
            ));
        }
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(body)
            .send()
            .await
            .map_err(|error| IntelligenceError::Unavailable(format!("POST {url}: {error}")))?;

        let status = response.status();
        if !status.is_success() {
            let detail = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            let detail = truncate(&detail, 500);
            return Err(IntelligenceError::Unavailable(format!(
                "POST {url} returned {status}: {detail}"
            )));
        }

        response
            .json::<T>()
            .await
            .map_err(|error| IntelligenceError::InvalidResponse(format!("POST {url}: {error}")))
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value.chars().take(max_chars).collect()
    }
}

#[derive(Debug, Deserialize)]
struct FindingsResponse {
    #[serde(default)]
    claims: Vec<ResearchClaim>,
    #[serde(default)]
    model_version: Option<String>,
}

#[async_trait::async_trait]
impl SalesIntelligence for HttpSalesIntelligence {
    async fn research_account(
        &self,
        req: &ResearchRequest<'_>,
    ) -> Result<ResearchFindings, IntelligenceError> {
        let body = serde_json::json!({
            "tenant_id": req.tenant_id,
            "account_id": req.account_id,
            "domain": req.domain,
            "company": req.company,
            "country": req.country,
            "industry": req.industry,
            "evidence": req.evidence,
            "model_version": self.model_version,
        });
        let response: FindingsResponse = self.post(RESEARCH_PATH, &body).await?;
        Ok(ResearchFindings {
            claims: response.claims,
            model_version: response
                .model_version
                .or_else(|| Some(self.model_version.clone())),
            fallback: None,
        })
    }

    async fn select_angle(
        &self,
        req: &AngleRequest<'_>,
    ) -> Result<AngleSelection, IntelligenceError> {
        let body = serde_json::json!({
            "tenant_id": req.tenant_id,
            "account_id": req.account_id,
            "evidence_ids": req.evidence_ids,
            "offer": req.offer,
            "persona": req.persona,
            "hypotheses": req.hypotheses,
        });
        self.post(ANGLE_PATH, &body).await
    }

    async fn draft_message(
        &self,
        req: &DraftRequest<'_>,
    ) -> Result<DraftedMessage, IntelligenceError> {
        let body = serde_json::json!({
            "tenant_id": req.tenant_id,
            "account_id": req.account_id,
            "contact_id": req.contact_id,
            "offer": req.offer,
            "angle": req.angle,
            "evidence": req.evidence,
            "language": req.language,
            "sender_name": req.sender_name,
            "company": req.company,
            "contact_name": req.contact_name,
        });
        let response: DraftedMessage = self.post(DRAFT_PATH, &body).await?;
        Ok(response)
    }

    async fn classify_reply(
        &self,
        req: &ReplyRequest<'_>,
    ) -> Result<ReplyClassification, IntelligenceError> {
        let body = serde_json::json!({
            "tenant_id": req.tenant_id,
            "enrollment_id": req.enrollment_id,
            "from": req.from,
            "subject": req.subject,
            "body": truncate(req.body, 20_000),
        });
        self.post(REPLY_PATH, &body).await
    }

    async fn determine_next_action(
        &self,
        req: &NextActionRequest<'_>,
    ) -> Result<DecisionAction, IntelligenceError> {
        let body = serde_json::json!({
            "tenant_id": req.tenant_id,
            "account_id": req.account_id,
            "contact_id": req.contact_id,
            "input": req.input,
        });
        #[derive(Deserialize)]
        struct Response {
            action: DecisionAction,
        }
        let response: Response = self.post(NEXT_ACTION_PATH, &body).await?;
        Ok(response.action)
    }
}

// ---------------------------------------------------------------------------
// Offline implementation
// ---------------------------------------------------------------------------

/// Why the offline implementation returns no new evidence.
pub const OFFLINE_RESEARCH_REASON: &str =
    "AI research is not configured or unavailable; offline mode writes no new evidence and uses \
     verified static content only (never an unevidenced claim)";

/// Deterministic, no-network intelligence. Used when no AI is configured and as
/// the fallback shape for outages.
#[derive(Debug, Default, Clone)]
pub struct OfflineIntelligence {
    model_version: String,
}

impl OfflineIntelligence {
    pub fn new() -> Self {
        Self {
            model_version: "offline-deterministic-v1".to_string(),
        }
    }

    pub fn model_version(&self) -> &str {
        &self.model_version
    }
}

/// Static, evidence-free message template. It asserts nothing about the
/// prospect; personalization fields are whatever the caller passed.
pub fn static_draft(req: &DraftRequest<'_>) -> DraftedMessage {
    let contact = req.contact_name.unwrap_or("there").trim();
    let greeting = if contact.is_empty() || contact.eq_ignore_ascii_case("there") {
        "Hi there".to_string()
    } else {
        format!("Hi {contact}")
    };
    let company_clause = req
        .company
        .map(|company| format!(" at {company}"))
        .unwrap_or_default();
    let offer_clause = match req.offer {
        Some(offer) if !offer.trim().is_empty() => {
            format!("how ApexMail's {} could help", offer.trim())
        }
        _ => "how ApexMail could help with your email infrastructure".to_string(),
    };
    let angle_clause = match req.angle {
        Some(angle) if !angle.trim().is_empty() => format!("Specifically: {}.", angle.trim()),
        _ => String::new(),
    };
    let subject = match req.company {
        Some(company) if !company.trim().is_empty() => {
            format!("Quick question about {}", company.trim())
        }
        _ => "Quick question about your email setup".to_string(),
    };
    let body = format!(
        "{greeting},\n\n\
         I'm reaching out{company_clause} to see whether {offer_clause} is worth a short \
         conversation. {angle_clause}\n\n\
         If this is not relevant, a one-line reply is enough and I will not follow up.\n\n\
         Best,\n{signature}",
        signature = req.sender_name.unwrap_or("The ApexMail team"),
    );
    DraftedMessage {
        subject,
        body,
        cited_evidence_ids: Vec::new(),
        // The static template makes no factual claims, so there is nothing to
        // ground and nothing to omit.
        claims: Vec::new(),
        fallback: Some(OFFLINE_RESEARCH_REASON.to_string()),
    }
}

/// Deterministic keyword classification, mirroring the dispositions in
/// `sales_reply_classifications` (migration 200:691-694).
pub fn classify_reply_deterministic(req: &ReplyRequest<'_>) -> ReplyClassification {
    let haystack = format!("{}\n{}", req.subject, req.body).to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|needle| haystack.contains(needle));

    let (disposition, confidence, reasoning, suggested) = if has(&[
        "unsubscribe",
        "opt out",
        "opt-out",
        "remove me",
        "stop emailing",
        "do not contact",
    ]) {
        (
            ReplyDisposition::Unsubscribe,
            0.95,
            "explicit opt-out language detected",
            Some(DecisionAction::StopPermanently),
        )
    } else if has(&["complaint", "spam", "report you", "abuse"]) {
        (
            ReplyDisposition::Complaint,
            0.85,
            "complaint language detected",
            Some(DecisionAction::StopPermanently),
        )
    } else if has(&[
        "out of office",
        "out-of-office",
        "automatic reply",
        "on vacation",
        "annual leave",
        "ooo",
    ]) {
        (
            ReplyDisposition::OutOfOffice,
            0.8,
            "automatic out-of-office language detected",
            Some(DecisionAction::Wait),
        )
    } else if has(&[
        "not interested",
        "no thanks",
        "no thank you",
        "pass on this",
    ]) {
        (
            ReplyDisposition::NotInterested,
            0.8,
            "explicit disinterest detected",
            Some(DecisionAction::StopPermanently),
        )
    } else if has(&[
        "meeting",
        "schedule",
        "calendar",
        "book a",
        "book time",
        "demo",
        "call next week",
    ]) {
        (
            ReplyDisposition::MeetingRequest,
            0.85,
            "meeting/scheduling language detected",
            Some(DecisionAction::BookMeeting),
        )
    } else if has(&["referred", "colleague", "forwarding", "right person"]) {
        (
            ReplyDisposition::Referral,
            0.7,
            "referral language detected",
            Some(DecisionAction::AskForReferral),
        )
    } else if haystack.contains('?')
        || has(&["pricing", "how much", "cost", "question", "tell me more"])
    {
        (
            ReplyDisposition::Question,
            0.6,
            "question or pricing language detected",
            Some(DecisionAction::OperatorTask),
        )
    } else if has(&[
        "yes",
        "interested",
        "sounds good",
        "let's talk",
        "lets talk",
        "happy to",
        "keen",
    ]) {
        (
            ReplyDisposition::Positive,
            0.6,
            "positive language detected",
            Some(DecisionAction::OperatorTask),
        )
    } else {
        (
            ReplyDisposition::Unknown,
            0.3,
            "no deterministic disposition matched",
            Some(DecisionAction::OperatorTask),
        )
    };

    ReplyClassification {
        disposition,
        confidence,
        reasoning: reasoning.to_string(),
        suggested_action: suggested,
    }
}

#[async_trait::async_trait]
impl SalesIntelligence for OfflineIntelligence {
    async fn research_account(
        &self,
        _req: &ResearchRequest<'_>,
    ) -> Result<ResearchFindings, IntelligenceError> {
        Ok(ResearchFindings {
            claims: Vec::new(),
            model_version: Some(self.model_version.clone()),
            fallback: Some(OFFLINE_RESEARCH_REASON.to_string()),
        })
    }

    async fn select_angle(
        &self,
        req: &AngleRequest<'_>,
    ) -> Result<AngleSelection, IntelligenceError> {
        let persona = req.persona.unwrap_or("the contact");
        let angle = match req.offer {
            Some(offer) if !offer.trim().is_empty() => {
                format!("{} for {persona}", offer.trim())
            }
            _ => format!("email-infrastructure fit for {persona}"),
        };
        Ok(AngleSelection {
            rationale: format!(
                "offline deterministic angle from offer '{}' and {} grounded evidence \
                 reference(s); no factual claim is asserted",
                req.offer.unwrap_or("none"),
                req.evidence_ids.len()
            ),
            angle,
            cited_evidence_ids: req.evidence_ids.to_vec(),
            hypothesis_based: req.offer.is_none(),
        })
    }

    async fn draft_message(
        &self,
        req: &DraftRequest<'_>,
    ) -> Result<DraftedMessage, IntelligenceError> {
        Ok(static_draft(req))
    }

    async fn classify_reply(
        &self,
        req: &ReplyRequest<'_>,
    ) -> Result<ReplyClassification, IntelligenceError> {
        Ok(classify_reply_deterministic(req))
    }

    async fn determine_next_action(
        &self,
        req: &NextActionRequest<'_>,
    ) -> Result<DecisionAction, IntelligenceError> {
        Ok(crate::experiments::next_best_action(req.input).0)
    }
}

// ---------------------------------------------------------------------------
// The evidence-grounding rule
// ---------------------------------------------------------------------------

/// A claim that survived [`validate_claims`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatedClaim {
    pub proposition: String,
    pub confidence: f64,
    pub source_kind: Option<String>,
    pub source_ref: Option<String>,
    /// Non-empty for factual claims; empty for a labelled hypothesis.
    pub evidence_ids: Vec<Uuid>,
    pub is_hypothesis: bool,
}

/// A claim that did not survive, with the reason it was omitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OmittedClaim {
    pub proposition: String,
    pub reason: String,
}

/// Result of applying the §12 rule.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClaimValidation {
    pub accepted: Vec<ValidatedClaim>,
    pub omitted: Vec<OmittedClaim>,
}

/// THE HARD RULE: every factual statement references at least one allowed
/// `evidence_id`; a statement that cannot is kept only as a labelled
/// hypothesis; otherwise it is omitted with a reason.
///
/// Omission reasons:
///
/// * empty proposition / non-finite confidence / confidence outside `0..=1`;
/// * a factual claim with no evidence id;
/// * any claim citing an evidence id that is not in the allowed set
///   (hallucinated citation).
pub fn validate_claims(claims: &[ResearchClaim], allowed_evidence_ids: &[Uuid]) -> ClaimValidation {
    let mut validation = ClaimValidation::default();
    for claim in claims {
        let proposition = claim.proposition.trim().to_string();
        if proposition.is_empty() {
            validation.omitted.push(OmittedClaim {
                proposition: String::new(),
                reason: "empty proposition; omitted".to_string(),
            });
            continue;
        }
        if !claim.confidence.is_finite() || !(0.0..=1.0).contains(&claim.confidence) {
            validation.omitted.push(OmittedClaim {
                proposition,
                reason: format!("confidence {} is outside 0..=1; omitted", claim.confidence),
            });
            continue;
        }
        match claim.evidence_id {
            Some(evidence_id) => {
                if !allowed_evidence_ids.contains(&evidence_id) {
                    validation.omitted.push(OmittedClaim {
                        proposition,
                        reason: format!(
                            "cites evidence id {evidence_id} which is not in the allowed set; \
                             a hallucinated citation is worse than no citation — omitted"
                        ),
                    });
                    continue;
                }
                validation.accepted.push(ValidatedClaim {
                    proposition,
                    confidence: claim.confidence,
                    source_kind: claim.source_kind.clone(),
                    source_ref: claim.source_ref.clone(),
                    evidence_ids: vec![evidence_id],
                    is_hypothesis: claim.is_hypothesis,
                });
            }
            None if claim.is_hypothesis => {
                validation.accepted.push(ValidatedClaim {
                    proposition,
                    confidence: claim.confidence,
                    source_kind: claim.source_kind.clone(),
                    source_ref: claim.source_ref.clone(),
                    evidence_ids: Vec::new(),
                    is_hypothesis: true,
                });
            }
            None => {
                validation.omitted.push(OmittedClaim {
                    proposition,
                    reason: "unevidenced factual claim: no allowed evidence_id and not marked as \
                             a hypothesis; omitted"
                        .to_string(),
                });
            }
        }
    }
    validation
}

/// Validate drafting claims as well; the same rule applies to message copy.
pub fn validate_draft_claims(
    claims: &[ResearchClaim],
    allowed_evidence_ids: &[Uuid],
) -> ClaimValidation {
    validate_claims(claims, allowed_evidence_ids)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(proposition: &str, evidence_id: Option<Uuid>, is_hypothesis: bool) -> ResearchClaim {
        ResearchClaim {
            proposition: proposition.to_string(),
            confidence: 0.7,
            source_kind: Some("provider_api".to_string()),
            source_ref: None,
            evidence_id,
            is_hypothesis,
        }
    }

    #[test]
    fn unevidenced_factual_claims_are_omitted() {
        let allowed = vec![Uuid::new_v4()];
        let validation = validate_claims(&[claim("They use SendGrid", None, false)], &allowed);
        assert!(validation.accepted.is_empty());
        assert_eq!(validation.omitted.len(), 1);
        assert!(validation.omitted[0].reason.contains("unevidenced"));
    }

    #[test]
    fn a_labelled_hypothesis_survives() {
        let allowed = vec![Uuid::new_v4()];
        let validation =
            validate_claims(&[claim("They may be replatforming", None, true)], &allowed);
        assert_eq!(validation.accepted.len(), 1);
        assert!(validation.accepted[0].is_hypothesis);
        assert!(validation.accepted[0].evidence_ids.is_empty());
        assert!(validation.omitted.is_empty());
    }

    #[test]
    fn a_hallucinated_citation_is_omitted_even_for_a_hypothesis() {
        let allowed = vec![Uuid::new_v4()];
        let hallucinated = Uuid::new_v4();
        let validation = validate_claims(
            &[
                claim("They use SendGrid", Some(hallucinated), false),
                claim("They may be replatforming", Some(hallucinated), true),
            ],
            &allowed,
        );
        assert!(validation.accepted.is_empty());
        assert_eq!(validation.omitted.len(), 2);
        for omitted in &validation.omitted {
            assert!(
                omitted.reason.contains("not in the allowed set"),
                "{}",
                omitted.reason
            );
        }
    }

    #[test]
    fn an_allowed_citation_survives() {
        let allowed_id = Uuid::new_v4();
        let validation = validate_claims(
            &[claim("They use SendGrid", Some(allowed_id), false)],
            &[allowed_id],
        );
        assert_eq!(validation.accepted.len(), 1);
        assert_eq!(validation.accepted[0].evidence_ids, vec![allowed_id]);
        assert!(!validation.accepted[0].is_hypothesis);
    }

    #[test]
    fn empty_or_miscalibrated_claims_are_omitted() {
        let allowed = vec![Uuid::new_v4()];
        let mut empty = claim("   ", Some(allowed[0]), false);
        empty.confidence = 0.5;
        let mut overconfident = claim("Confident", Some(allowed[0]), false);
        overconfident.confidence = 1.5;
        let mut nan = claim("NaN", Some(allowed[0]), false);
        nan.confidence = f64::NAN;
        let validation = validate_claims(&[empty, overconfident, nan], &allowed);
        assert!(validation.accepted.is_empty());
        assert_eq!(validation.omitted.len(), 3);
        assert!(validation.omitted[0].reason.contains("empty"));
        assert!(validation.omitted[1].reason.contains("outside 0..=1"));
        assert!(validation.omitted[2].reason.contains("outside 0..=1"));
    }

    #[test]
    fn validation_never_panics_on_hostile_input() {
        let allowed = vec![Uuid::new_v4()];
        let huge = claim(&"x".repeat(1_000_000), Some(allowed[0]), false);
        let validation = validate_claims(&[huge], &allowed);
        assert_eq!(validation.accepted.len(), 1);
    }

    #[tokio::test]
    async fn offline_research_returns_no_claims_and_a_reason() {
        let intelligence = OfflineIntelligence::new();
        let findings = intelligence
            .research_account(&ResearchRequest {
                tenant_id: "t",
                account_id: None,
                domain: "acme.example",
                company: Some("Acme"),
                country: Some("DE"),
                industry: Some("saas"),
                evidence: &[],
            })
            .await
            .expect("offline research works");
        assert!(findings.claims.is_empty());
        assert!(findings.fallback.is_some());
        assert!(findings
            .fallback
            .unwrap()
            .contains("writes no new evidence"));
    }

    #[tokio::test]
    async fn offline_draft_is_static_verified_content() {
        let intelligence = OfflineIntelligence::new();
        let drafted = intelligence
            .draft_message(&DraftRequest {
                tenant_id: "t",
                account_id: None,
                contact_id: None,
                offer: Some("deliverability audit"),
                angle: None,
                evidence: &[],
                language: Some("en"),
                sender_name: Some("Ann"),
                company: Some("Acme"),
                contact_name: Some("Bob"),
            })
            .await
            .unwrap();
        assert!(drafted.subject.contains("Acme"));
        assert!(drafted.body.contains("Bob"));
        assert!(drafted.body.contains("deliverability audit"));
        assert!(drafted.claims.is_empty(), "static content claims nothing");
        assert!(drafted.fallback.is_some());
    }

    #[tokio::test]
    async fn offline_reply_classification_is_deterministic() {
        let intelligence = OfflineIntelligence::new();
        let cases = [
            ("please unsubscribe me", ReplyDisposition::Unsubscribe),
            ("Can we schedule a demo?", ReplyDisposition::MeetingRequest),
            (
                "I'm out of office until Monday",
                ReplyDisposition::OutOfOffice,
            ),
            ("No thanks, not interested", ReplyDisposition::NotInterested),
            ("Yes, interested — let's talk", ReplyDisposition::Positive),
            ("What does pricing look like?", ReplyDisposition::Question),
            ("Talk to my colleague instead", ReplyDisposition::Referral),
            ("Lorem ipsum dolor", ReplyDisposition::Unknown),
        ];
        for (body, expected) in cases {
            let classification = intelligence
                .classify_reply(&ReplyRequest {
                    tenant_id: "t",
                    enrollment_id: None,
                    from: "x@example.com",
                    subject: "Re: outreach",
                    body,
                })
                .await
                .unwrap();
            assert_eq!(classification.disposition, expected, "body: {body}");
            assert!(classification.confidence > 0.0);
            assert!(!classification.reasoning.is_empty());
        }
    }

    #[tokio::test]
    async fn offline_next_action_matches_the_pure_policy() {
        use crate::experiments::{next_best_action, NextActionInput};
        let intelligence = OfflineIntelligence::new();
        let input = NextActionInput {
            expected_value_eur: 1.0,
            evidence_count: 0,
            email: crate::experiments::EmailState::Unverified,
            ..NextActionInput::default()
        };
        let action = intelligence
            .determine_next_action(&NextActionRequest {
                tenant_id: "t",
                account_id: None,
                contact_id: None,
                input: &input,
            })
            .await
            .unwrap();
        assert_eq!(action, next_best_action(&input).0);
        assert_eq!(action, DecisionAction::DoNothing);
    }

    #[test]
    fn env_configured_http_provider_is_built() {
        // `from_env` is only testable serially; assert the constructor + config
        // surface instead of mutating process env.
        let http = HttpSalesIntelligence::new("https://ai.example.com/", "key");
        assert_eq!(http.base_url(), "https://ai.example.com");
        assert_eq!(http.model_version(), "apexmail-ai");
        assert_eq!(
            format!("{}{}", http.base_url(), RESEARCH_PATH),
            "https://ai.example.com/v1/sales/research"
        );
    }

    #[test]
    fn truncate_never_splits_a_character() {
        let value = "ä".repeat(1_000);
        let truncated = truncate(&value, 10);
        assert_eq!(truncated.chars().count(), 10);
    }
}
