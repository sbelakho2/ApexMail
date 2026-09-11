//! Structured message strategist (audit §14).
//!
//! Personalization used to be string templating. This module replaces it with
//! a **structured decision about what to say, produced before any prose**:
//!
//! ```text
//! StrategyRequest (ids + offer + experiment arm)
//!   → MessageStrategist::build()          reads canonical tables
//!   → StrategyInput                       (account, contact, evidence, signals, …)
//!   → compose_strategy()                  structured MessageStrategy
//!   → validate_strategy()                 drops unevidenced claims
//!   → render_cold_email(writer)           four-part email via a ProseWriter
//! ```
//!
//! # The hard grounding rule (audit §12/§14)
//!
//! Every AI-generated factual statement must either reference at least one
//! `evidence_id` or be explicitly classified as a hypothesis. If neither is
//! possible it is **omitted**. This is enforced in code:
//!
//! * [`ObservedFact`] carries a mandatory `evidence_id`; a nil id is treated
//!   as absent and the fact is dropped by [`validate_strategy`].
//! * [`ProofPoint`] must carry an evidence id OR a verified,
//!   external-copy-allowed knowledge fact id; otherwise it is dropped.
//! * [`MessageStrategy::problem_hypothesis`] is the one field that is
//!   *classified* as a hypothesis by construction.
//! * [`SalesKnowledgeBase::validate_claim`] additionally blocks any part that
//!   promises a restricted capability (SSO, SLA terms, migration,
//!   certifications) without a backed fact.
//!
//! # Fake personalization is banned
//!
//! [`BANNED_FAKE_PERSONALIZATION_PATTERNS`] lists the phrase families that
//! must never appear in cold copy. The `"i noticed you use …"` family is
//! conditionally allowed: only when an evidence-backed [`ObservedFact`]
//! actually names the referenced technology.
//!
//! # No LLM coupling
//!
//! Prose generation goes through the [`ProseWriter`] trait.
//! [`TemplateProseWriter`] is a deterministic, offline implementation used
//! when no AI is configured, so the module is fully testable without network
//! access.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::knowledge::{ClaimVerdict, KnowledgeSource, SalesKnowledgeBase};

/// Minimum evidence confidence for an observation to be used as the one
/// genuine personalized fact in cold copy.
pub const MIN_OBSERVED_CONFIDENCE: f32 = 0.5;
/// Minimum evidence confidence for an evidence row to serve as a proof point.
pub const MIN_PROOF_CONFIDENCE: f32 = 0.7;
/// Maximum number of signals considered (highest strength first). Bounds
/// memory/latency on hostile accounts with thousands of signals.
pub const MAX_SIGNALS_CONSIDERED: usize = 100;
/// Maximum length of any single strategy field. Oversized input from a
/// hostile database row is truncated, never panicked on.
pub const MAX_FIELD_CHARS: usize = 20_000;

/// Delivery tone, derived from persona/seniority/interaction history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    #[default]
    Consultative,
    Direct,
    Technical,
    Warm,
}

/// A genuine, evidence-backed observation about the prospect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedFact {
    pub statement: String,
    /// MUST be a real `sales_evidence.id`. A nil id is treated as absent.
    pub evidence_id: Uuid,
    pub confidence: f32,
}

/// A proof point: evidence about the prospect OR a verified knowledge fact
/// about ApexMail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofPoint {
    pub statement: String,
    pub evidence_id: Option<Uuid>,
    pub knowledge_fact_id: Option<String>,
}

/// Structured decision about what to say, produced BEFORE any prose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageStrategy {
    pub observed_fact: Option<ObservedFact>,
    pub problem_hypothesis: String,
    pub value_prop: String,
    pub proof_point: Option<ProofPoint>,
    pub offer: String,
    pub cta: String,
    pub tone: Tone,
    pub language: String,
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Account row context (`sales_accounts`,
/// `migrations/200_sales_autopilot_v2_unification.sql:212-247`).
#[derive(Debug, Clone, Default)]
pub struct AccountContext {
    pub company: String,
    pub domain: String,
    pub country: Option<String>,
    pub industry: Option<String>,
    pub employees: Option<i32>,
    pub technologies: Vec<String>,
    /// `sales_accounts.esp_hypotheses` — hypotheses, never facts
    /// (`migrations/200_sales_autopilot_v2_unification.sql:226`).
    pub esp_hypotheses: Vec<String>,
}

/// Contact row context (`sales_contacts`,
/// `migrations/200_sales_autopilot_v2_unification.sql:250-270`).
#[derive(Debug, Clone, Default)]
pub struct ContactContext {
    pub full_name: String,
    pub job_title: Option<String>,
    pub persona: Option<String>,
    pub country: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
}

/// A signal row (`sales_signals`,
/// `migrations/200_sales_autopilot_v2_unification.sql:377-395`).
#[derive(Debug, Clone)]
pub struct SignalContext {
    pub signal_type: String,
    pub strength: f32,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub evidence_id: Option<Uuid>,
    pub payload: serde_json::Value,
}

/// An evidence row (`sales_evidence`,
/// `migrations/200_sales_autopilot_v2_unification.sql:308-330`).
#[derive(Debug, Clone)]
pub struct EvidenceContext {
    pub id: Uuid,
    pub proposition: String,
    pub confidence: f32,
    pub source_kind: String,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// A previous touch (`sales_step_executions`,
/// `migrations/200_sales_autopilot_v2_unification.sql:523-552`).
#[derive(Debug, Clone, Default)]
pub struct TouchContext {
    pub attempt_kind: String,
    pub state: String,
    pub executed_at: Option<DateTime<Utc>>,
    pub variant: String,
}

/// A prior reply classification (`sales_reply_classifications`,
/// `migrations/200_sales_autopilot_v2_unification.sql:684-706`).
#[derive(Debug, Clone)]
pub struct ReplyContext {
    pub disposition: String,
    pub confidence: f32,
    pub created_at: DateTime<Utc>,
}

/// Current-stack hypothesis from `sales_enrichment_facts` /
/// `sales_evidence` (`migrations/200_sales_autopilot_v2_unification.sql:336-352`).
#[derive(Debug, Clone)]
pub struct StackHypothesis {
    pub field: String,
    pub value: String,
    pub provider: String,
    pub confidence: f32,
    pub evidence_id: Option<Uuid>,
}

/// Experiment arm the contact is enrolled in (`sales_experiments` /
/// `sales_experiment_arms`, `migrations/200_sales_autopilot_v2_unification.sql:788-813`
/// and the enrollment's `experiment_id` / `experiment_variant` columns at
/// `491-515`).
#[derive(Debug, Clone, Default)]
pub struct ExperimentArm {
    pub experiment_id: Option<Uuid>,
    pub variant: String,
    pub is_control: bool,
}

/// Everything the composition step needs, already loaded. The pure
/// [`compose_strategy`] takes this so it can be tested without a database.
#[derive(Debug, Clone, Default)]
pub struct StrategyInput {
    pub account: AccountContext,
    pub contact: ContactContext,
    pub signals: Vec<SignalContext>,
    pub evidence: Vec<EvidenceContext>,
    pub previous_touches: Vec<TouchContext>,
    pub reply_history: Vec<ReplyContext>,
    pub stack_hypothesis: Vec<StackHypothesis>,
    /// Chosen commercial offer.
    pub offer: String,
    pub experiment_arm: Option<ExperimentArm>,
    /// Explicit language override; the contact's language is the fallback.
    pub language: Option<String>,
    /// Clock injection for determinism.
    pub now: Option<DateTime<Utc>>,
    /// Verified knowledge base used for value props and proof points.
    /// Defaults to an empty base (no product claims) — callers should pass
    /// [`SalesKnowledgeBase::canonical`] or their own approved set.
    pub knowledge: SalesKnowledgeBase,
}

/// A request to build a strategy for one enrolled contact.
#[derive(Debug, Clone)]
pub struct StrategyRequest {
    pub tenant_id: String,
    pub account_id: Uuid,
    pub contact_id: Uuid,
    pub enrollment_id: Option<Uuid>,
    /// Explicit language override (ISO 639-1, may carry a region).
    pub language: Option<String>,
    /// The chosen commercial offer for this contact.
    pub offer: String,
    pub experiment_arm: Option<ExperimentArm>,
    pub now: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StrategistError {
    #[error("account or contact not found: {0}")]
    NotFound(String),
    #[error("strategist database error: {0}")]
    Database(String),
}

// ---------------------------------------------------------------------------
// Banned fake personalization
// ---------------------------------------------------------------------------

/// Phrase families that are banned from cold copy. They claim familiarity
/// that was never established and destroy trust when the prospect asks "what
/// exactly did you read?".
///
/// The `"i noticed you use"` family is conditionally allowed: it may appear
/// only when the strategy carries an evidence-backed observation that names
/// the referenced technology (see [`pattern_requires_evidence`]).
///
/// The comparison is case-insensitive and accent-naive (ASCII lowercase).
pub const BANNED_FAKE_PERSONALIZATION_PATTERNS: &[&str] = &[
    "i've been following",
    "i have been following",
    "i noticed you use",
    "i noticed that you use",
    "i came across your",
    "i'm impressed by your",
    "i am impressed by your",
    "impressed by your",
    "i love what you're doing",
    "huge fan of",
    "as a fellow",
    "caught my eye",
    "long-time follower",
    "longtime follower",
    "been watching your",
];

/// Patterns from [`BANNED_FAKE_PERSONALIZATION_PATTERNS`] that MAY be used
/// when, and only when, an evidence-backed observation names the technology
/// the phrase refers to.
pub const EVIDENCE_CONDITIONAL_PATTERNS: &[&str] = &["i noticed you use", "i noticed that you use"];

/// Is this banned pattern conditionally allowed with evidence?
pub fn pattern_requires_evidence(pattern: &str) -> bool {
    EVIDENCE_CONDITIONAL_PATTERNS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(pattern))
}

/// Return the first banned pattern found in `text`, if any.
pub fn find_banned_personalization(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    BANNED_FAKE_PERSONALIZATION_PATTERNS
        .iter()
        .find(|pattern| lower.contains(**pattern))
        .copied()
}

/// Extract the technology token(s) following a `"noticed you use …"` phrase.
fn technology_after_use(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let (index, marker) = EVIDENCE_CONDITIONAL_PATTERNS
        .iter()
        .filter_map(|marker| lower.find(marker).map(|index| (index, *marker)))
        .min_by_key(|(index, _)| *index)?;
    let tail = &text[index + marker.len()..];
    let token = tail
        .split_whitespace()
        .next()
        .map(|word| {
            word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.' && c != '+')
        })
        .filter(|word| word.len() > 2)?;
    Some(token.to_string())
}

/// High-pressure CTA phrases that violate the "one low-friction CTA" rule.
const HIGH_PRESSURE_CTA_PATTERNS: &[&str] = &[
    "buy now",
    "sign today",
    "act now",
    "limited time",
    "call me immediately",
    "don't miss out",
    "last chance",
];

// ---------------------------------------------------------------------------
// Composition (pure)
// ---------------------------------------------------------------------------

/// Compose the structured strategy. Pure: no database, no network, no clock
/// (the clock comes from `input.now`).
pub fn compose_strategy(input: &StrategyInput) -> MessageStrategy {
    let now = input.now.unwrap_or_else(Utc::now);

    // 1. Exactly one genuine observed fact: the highest-confidence, in-date,
    //    sufficiently-confident piece of evidence.
    let observed_fact = input
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.confidence >= MIN_OBSERVED_CONFIDENCE
                && evidence.confidence.is_finite()
                && evidence.expires_at.is_none_or(|expires| expires > now)
                && !evidence.proposition.trim().is_empty()
        })
        .max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|evidence| ObservedFact {
            statement: truncate(&evidence.proposition, MAX_FIELD_CHARS),
            evidence_id: evidence.id,
            confidence: evidence.confidence,
        });

    // 2. One problem hypothesis, derived from the strongest live signal and
    //    the persona. Explicitly a hypothesis — never a factual claim.
    let problem_hypothesis = derive_problem_hypothesis(input, now);

    // 3. One value proposition grounded in a verified knowledge fact.
    let value_prop = select_value_prop(input);

    // 4. One proof point: prospect evidence if available, else a verified
    //    external-copy knowledge fact. Omitting is allowed (and validated).
    let proof_point = select_proof_point(input, now, value_prop.as_str());

    let language = resolve_language(input);
    let cta = default_cta(&language);
    let tone = derive_tone(input);

    MessageStrategy {
        observed_fact,
        problem_hypothesis: truncate(&problem_hypothesis, MAX_FIELD_CHARS),
        value_prop: truncate(&value_prop, MAX_FIELD_CHARS),
        proof_point,
        offer: truncate(input.offer.trim(), MAX_FIELD_CHARS),
        cta,
        tone,
        language,
    }
}

fn derive_problem_hypothesis(input: &StrategyInput, now: DateTime<Utc>) -> String {
    let mut live: Vec<&SignalContext> = input
        .signals
        .iter()
        .filter(|signal| signal.expires_at.is_none_or(|expires| expires > now))
        .collect();
    live.sort_by(|a, b| {
        b.strength
            .partial_cmp(&a.strength)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let dominant = live.first().map(|signal| signal.signal_type.as_str());

    let industry = input.account.industry.as_deref().unwrap_or("your industry");
    match dominant {
        Some(kind) if contains_ci(kind, "hiring") || contains_ci(kind, "headcount") => format!(
            "Our hypothesis: rapid hiring at {} is putting pressure on the systems that send customer email.",
            input.account.company
        ),
        Some(kind) if contains_ci(kind, "funding") => format!(
            "Our hypothesis: after the recent funding news, {} is scaling its customer communications.",
            input.account.company
        ),
        Some(kind) if contains_ci(kind, "email") || contains_ci(kind, "esp") => format!(
            "Our hypothesis: {} has outgrown the current email provider's deliverability guarantees.",
            input.account.company
        ),
        Some(kind) if contains_ci(kind, "competitor") || contains_ci(kind, "stack") => format!(
            "Our hypothesis: the current email stack at {} was chosen before your volume and compliance needs grew.",
            input.account.company
        ),
        _ => format!(
            "Our hypothesis: teams in {industry} lose engineering time on email infrastructure instead of their product."
        ),
    }
}

fn select_value_prop(input: &StrategyInput) -> String {
    // Prefer a shipping-capability fact whose wording overlaps the offer.
    // Only external-copy-allowed facts are eligible; the wording is used
    // as-is because the knowledge base owns the phrasing.
    let tokens = tokenize(&input.offer);
    let technologies = tokenize(&input.account.technologies.join(" "));
    let best = input
        .knowledge
        .external_copy_facts()
        .into_iter()
        .max_by_key(|fact| {
            let claim_tokens = tokenize(&fact.claim);
            let overlap = claim_tokens
                .iter()
                .filter(|token| tokens.contains(token) || technologies.contains(token))
                .count();
            // Prefer capability facts over pricing when tied.
            overlap * 2
                + usize::from(matches!(
                    fact.source,
                    KnowledgeSource::FeatureRegistry | KnowledgeSource::ProductDocs
                ))
        });
    match best {
        Some(fact) => fact.claim.clone(),
        None => {
            "ApexMail gives engineering teams a reliable email API with deliverability built in."
                .to_string()
        }
    }
}

fn select_proof_point(
    input: &StrategyInput,
    _now: DateTime<Utc>,
    value_prop: &str,
) -> Option<ProofPoint> {
    // Prospect-side proof (their own observed stack) wins when it is
    // strong and evidence-backed.
    if let Some(hypothesis) = input
        .stack_hypothesis
        .iter()
        .filter(|item| item.confidence >= MIN_PROOF_CONFIDENCE)
        .max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    {
        if let Some(evidence_id) = hypothesis.evidence_id.filter(|id| !id.is_nil()) {
            return Some(ProofPoint {
                statement: truncate(
                    &format!(
                        "{} is observed using {}.",
                        input.account.company, hypothesis.value
                    ),
                    MAX_FIELD_CHARS,
                ),
                evidence_id: Some(evidence_id),
                knowledge_fact_id: None,
            });
        }
    }
    // Otherwise a verified knowledge fact distinct from the value prop.
    input
        .knowledge
        .external_copy_facts()
        .into_iter()
        .find(|fact| fact.claim != value_prop)
        .map(|fact| ProofPoint {
            statement: truncate(&fact.claim, MAX_FIELD_CHARS),
            evidence_id: None,
            knowledge_fact_id: Some(fact.id.clone()),
        })
}

fn derive_tone(input: &StrategyInput) -> Tone {
    let persona = input
        .contact
        .persona
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let title = input
        .contact
        .job_title
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let positive_reply = input.reply_history.iter().any(|reply| {
        matches!(
            reply.disposition.to_ascii_lowercase().as_str(),
            "positive" | "meeting_request"
        )
    });
    if positive_reply {
        return Tone::Warm;
    }
    if persona.contains("executive")
        || persona.contains("c-level")
        || persona.contains("founder")
        || title.contains("ceo")
        || title.contains("cto")
        || title.contains("vp")
    {
        return Tone::Direct;
    }
    if persona.contains("technical")
        || persona.contains("engineer")
        || title.contains("engineer")
        || title.contains("developer")
    {
        return Tone::Technical;
    }
    Tone::Consultative
}

/// Resolve the outreach language: explicit override, then contact language,
/// then `en`. An empty/whitespace value falls back to `en` (documented).
pub fn resolve_language(input: &StrategyInput) -> String {
    input
        .language
        .as_deref()
        .or(input.contact.language.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| truncate(value, 35))
        .unwrap_or_else(|| "en".to_string())
}

fn default_cta(language: &str) -> String {
    let primary = language
        .split(['-', '_'])
        .next()
        .unwrap_or("en")
        .to_ascii_lowercase();
    let text = match primary.as_str() {
        "et" => "Kas 15-minutiline kõne järgmisel nädalal oleks kasulik?",
        "de" => "Wäre ein 15-minütiges Gespräch nächste Woche hilfreich?",
        "fr" => "Un échange de 15 minutes la semaine prochaine serait-il utile ?",
        "fi" => "Olisiko 15 minuutin keskustelu ensi viikolla hyödyllinen?",
        _ => "Would a 15-minute call next week be useful?",
    };
    text.to_string()
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| token.len() > 2)
        .map(str::to_string)
        .collect()
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.trim().to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// A validation violation; the offending part is omitted from the sanitized
/// strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StrategyViolation {
    /// An observed fact without a usable evidence id (nil) was omitted.
    ObservedFactWithoutEvidence { statement: String },
    /// An observed fact with non-finite/out-of-range confidence was omitted.
    ObservedFactInvalidConfidence { statement: String },
    /// A proof point with neither evidence nor a verified knowledge fact was
    /// omitted.
    ProofPointUnbacked { statement: String },
    /// The value prop promises something no external-copy fact backs; the
    /// renderer refuses rather than sending it.
    UnsupportedValueProp { capability: String, reason: String },
}

/// Result of validation: a sanitized strategy plus what was removed and why.
#[derive(Debug, Clone)]
pub struct StrategyValidation {
    pub strategy: MessageStrategy,
    pub violations: Vec<StrategyViolation>,
}

/// Enforce the grounding rule: drop any observed fact without an evidence id
/// and any proof point with neither evidence nor a verified knowledge fact.
pub fn validate_strategy(
    strategy: &MessageStrategy,
    knowledge: &SalesKnowledgeBase,
) -> StrategyValidation {
    let mut sanitized = strategy.clone();
    let mut violations = Vec::new();

    if let Some(observed) = &strategy.observed_fact {
        if observed.evidence_id.is_nil() {
            violations.push(StrategyViolation::ObservedFactWithoutEvidence {
                statement: observed.statement.clone(),
            });
            sanitized.observed_fact = None;
        } else if !observed.confidence.is_finite()
            || observed.confidence < 0.0
            || observed.confidence > 1.0
        {
            violations.push(StrategyViolation::ObservedFactInvalidConfidence {
                statement: observed.statement.clone(),
            });
            sanitized.observed_fact = None;
        }
    }

    if let Some(proof) = &strategy.proof_point {
        let evidence_ok = proof.evidence_id.is_some_and(|id| !id.is_nil());
        let knowledge_ok = proof
            .knowledge_fact_id
            .as_deref()
            .and_then(|id| knowledge.get(id))
            .is_some_and(|fact| fact.is_external_copy_allowed_at(Utc::now()));
        if !evidence_ok && !knowledge_ok {
            violations.push(StrategyViolation::ProofPointUnbacked {
                statement: proof.statement.clone(),
            });
            sanitized.proof_point = None;
        }
    }

    if let ClaimVerdict::Unsupported { capability, reason } =
        knowledge.validate_claim(&strategy.value_prop)
    {
        violations.push(StrategyViolation::UnsupportedValueProp { capability, reason });
    }

    StrategyValidation {
        strategy: sanitized,
        violations,
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The four cold-composition parts. Exactly one of each (observation may be
/// absent when no evidence exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProsePart {
    ObservedFact,
    ProblemValue,
    ProofPoint,
    CallToAction,
    Subject,
    Body,
}

/// Request handed to a [`ProseWriter`].
#[derive(Debug)]
pub struct ProseRequest<'a> {
    pub part: ProsePart,
    pub strategy: &'a MessageStrategy,
}

#[derive(Debug, thiserror::Error)]
pub enum ProseError {
    #[error("prose writer cannot render {part:?}: {reason}")]
    CannotRender { part: ProsePart, reason: String },
}

/// Prose generation is pluggable: an AI-backed writer can be supplied when
/// configured, and `TemplateProseWriter` is the deterministic offline
/// implementation used otherwise. The strategist never depends on one LLM
/// provider.
pub trait ProseWriter: Send + Sync + std::fmt::Debug {
    fn write(&self, request: &ProseRequest<'_>) -> Result<String, ProseError>;
}

/// Deterministic template writer — no model, no network, stable output.
#[derive(Debug, Clone, Default)]
pub struct TemplateProseWriter;

impl TemplateProseWriter {
    pub fn new() -> Self {
        Self
    }

    fn greeting(&self, language: &str) -> &'static str {
        match language
            .split(['-', '_'])
            .next()
            .unwrap_or("en")
            .to_ascii_lowercase()
            .as_str()
        {
            "et" => "Tere",
            "de" => "Hallo",
            "fr" => "Bonjour",
            "fi" => "Hei",
            "ja" => "こんにちは",
            _ => "Hi",
        }
    }

    fn sign_off(&self, language: &str) -> &'static str {
        match language
            .split(['-', '_'])
            .next()
            .unwrap_or("en")
            .to_ascii_lowercase()
            .as_str()
        {
            "et" => "Parimate soovidega",
            "de" => "Viele Grüße",
            "fr" => "Bien cordialement",
            "fi" => "Ystävällisin terveisin",
            _ => "Best regards",
        }
    }
}

impl ProseWriter for TemplateProseWriter {
    fn write(&self, request: &ProseRequest<'_>) -> Result<String, ProseError> {
        let strategy = request.strategy;
        match request.part {
            ProsePart::ObservedFact => strategy
                .observed_fact
                .as_ref()
                .map(|fact| fact.statement.clone())
                .ok_or(ProseError::CannotRender {
                    part: request.part,
                    reason: "no evidence-backed observation".into(),
                }),
            ProsePart::ProblemValue => Ok(format!(
                "{} {}",
                strategy.problem_hypothesis.trim(),
                strategy.value_prop.trim()
            )
            .trim()
            .to_string()),
            ProsePart::ProofPoint => strategy
                .proof_point
                .as_ref()
                .map(|proof| proof.statement.clone())
                .ok_or(ProseError::CannotRender {
                    part: request.part,
                    reason: "no grounded proof point".into(),
                }),
            ProsePart::CallToAction => Ok(strategy.cta.trim().to_string()),
            ProsePart::Subject => Ok(truncate(
                &format!("Quick question about {}", strategy.offer.trim()),
                120,
            )),
            ProsePart::Body => {
                let mut parts: Vec<String> = vec![format!(
                    "{}, {}",
                    self.greeting(&strategy.language),
                    strategy.problem_hypothesis.trim()
                )];
                parts.push(strategy.value_prop.trim().to_string());
                if let Some(observed) = &strategy.observed_fact {
                    parts.push(observed.statement.clone());
                }
                if let Some(proof) = &strategy.proof_point {
                    parts.push(proof.statement.clone());
                }
                parts.push(strategy.cta.trim().to_string());
                parts.push(format!("—\n{}", self.sign_off(&strategy.language)));
                Ok(parts
                    .into_iter()
                    .filter(|part| !part.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n\n"))
            }
        }
    }
}

/// Why cold-composition rendering was refused.
#[derive(Debug, thiserror::Error)]
pub enum RenderRejection {
    #[error("fabricated personalization: the phrase {pattern:?} is banned ({reason})")]
    FakePersonalization {
        pattern: &'static str,
        reason: String,
    },
    #[error("unsupported claim in {part}: {reason}")]
    UnsupportedClaim {
        part: &'static str,
        capability: String,
        reason: String,
    },
    #[error("required part is missing or empty: {part}")]
    MissingRequiredPart { part: &'static str },
    #[error("high-pressure CTA {pattern:?} violates the low-friction rule")]
    HighPressureCta { pattern: &'static str },
    #[error(transparent)]
    Prose(#[from] ProseError),
}

/// The rendered four-part email plus the sanitized strategy's decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedStrategy {
    pub observed_fact: Option<String>,
    pub problem_value: String,
    pub proof_point: Option<String>,
    pub cta: String,
    pub subject: String,
    pub body: String,
    pub language: String,
    pub tone: Tone,
    /// Parts dropped by validation, with reasons.
    pub omitted: Vec<StrategyViolation>,
}

/// Render the four-part cold email from a strategy.
///
/// Refuses (with a clear reason) when:
/// * a banned fake-personalization pattern appears without evidence backing
///   the referenced technology;
/// * any part promises a restricted capability with no verified
///   external-copy fact;
/// * the value proposition or CTA is missing/empty;
/// * the CTA is high-pressure.
pub fn render_cold_email(
    strategy: &MessageStrategy,
    writer: &dyn ProseWriter,
    knowledge: &SalesKnowledgeBase,
) -> Result<RenderedStrategy, RenderRejection> {
    let validation = validate_strategy(strategy, knowledge);
    let sanitized = validation.strategy;

    // ── Fake-personalization ban ────────────────────────────────────────
    let all_text = [
        sanitized
            .observed_fact
            .as_ref()
            .map(|fact| fact.statement.as_str())
            .unwrap_or(""),
        sanitized.problem_hypothesis.as_str(),
        sanitized.value_prop.as_str(),
        sanitized
            .proof_point
            .as_ref()
            .map(|proof| proof.statement.as_str())
            .unwrap_or(""),
        sanitized.cta.as_str(),
        sanitized.offer.as_str(),
    ]
    .join("\n");
    if let Some(pattern) = find_banned_personalization(&all_text) {
        let backed = pattern_requires_evidence(pattern)
            && sanitized
                .observed_fact
                .as_ref()
                .is_some_and(|fact| !fact.evidence_id.is_nil())
            && technology_after_use(&all_text).is_some_and(|technology| {
                sanitized.observed_fact.as_ref().is_some_and(|fact| {
                    fact.statement
                        .to_lowercase()
                        .contains(&technology.to_lowercase())
                })
            });
        if !backed {
            return Err(RenderRejection::FakePersonalization {
                pattern,
                reason: "cold copy may not claim familiarity that is not backed by an evidence id"
                    .into(),
            });
        }
    }

    // ── Restricted-capability control ───────────────────────────────────
    for (part, text) in [
        ("value_prop", sanitized.value_prop.as_str()),
        (
            "proof_point",
            sanitized
                .proof_point
                .as_ref()
                .map(|proof| proof.statement.as_str())
                .unwrap_or(""),
        ),
        (
            "observed_fact",
            sanitized
                .observed_fact
                .as_ref()
                .map(|fact| fact.statement.as_str())
                .unwrap_or(""),
        ),
    ] {
        if let ClaimVerdict::Unsupported { capability, reason } = knowledge.validate_claim(text) {
            return Err(RenderRejection::UnsupportedClaim {
                part,
                capability,
                reason,
            });
        }
    }

    // ── Required parts ──────────────────────────────────────────────────
    if sanitized.value_prop.trim().is_empty() {
        return Err(RenderRejection::MissingRequiredPart { part: "value_prop" });
    }
    let cta = sanitized.cta.trim();
    if cta.is_empty() {
        return Err(RenderRejection::MissingRequiredPart { part: "cta" });
    }
    let cta_lower = cta.to_lowercase();
    if let Some(pattern) = HIGH_PRESSURE_CTA_PATTERNS
        .iter()
        .find(|pattern| cta_lower.contains(**pattern))
    {
        return Err(RenderRejection::HighPressureCta { pattern });
    }

    // ── Prose ───────────────────────────────────────────────────────────
    let observed_fact = match sanitized.observed_fact.as_ref() {
        Some(_) => Some(writer.write(&ProseRequest {
            part: ProsePart::ObservedFact,
            strategy: &sanitized,
        })?),
        None => None,
    };
    let problem_value = writer.write(&ProseRequest {
        part: ProsePart::ProblemValue,
        strategy: &sanitized,
    })?;
    let proof_point = match sanitized.proof_point.as_ref() {
        Some(_) => Some(writer.write(&ProseRequest {
            part: ProsePart::ProofPoint,
            strategy: &sanitized,
        })?),
        None => None,
    };
    let rendered_cta = writer.write(&ProseRequest {
        part: ProsePart::CallToAction,
        strategy: &sanitized,
    })?;
    let subject = writer.write(&ProseRequest {
        part: ProsePart::Subject,
        strategy: &sanitized,
    })?;
    let body = writer.write(&ProseRequest {
        part: ProsePart::Body,
        strategy: &sanitized,
    })?;

    Ok(RenderedStrategy {
        observed_fact,
        problem_value,
        proof_point,
        cta: rendered_cta,
        subject,
        body,
        language: sanitized.language.clone(),
        tone: sanitized.tone,
        omitted: validation.violations,
    })
}

// ---------------------------------------------------------------------------
// Database builder
// ---------------------------------------------------------------------------

/// Async builder that reads the canonical tables and composes a strategy.
#[derive(Debug, Clone)]
pub struct MessageStrategist {
    db: PgPool,
    knowledge: SalesKnowledgeBase,
}

impl MessageStrategist {
    pub fn new(db: PgPool, knowledge: SalesKnowledgeBase) -> Self {
        Self { db, knowledge }
    }

    pub fn knowledge(&self) -> &SalesKnowledgeBase {
        &self.knowledge
    }

    /// Load the canonical context for a request.
    pub async fn load_input(
        &self,
        request: &StrategyRequest,
    ) -> Result<StrategyInput, StrategistError> {
        let account_row: Option<(
            String,
            String,
            Option<String>,
            Option<String>,
            Option<i32>,
            Vec<String>,
            serde_json::Value,
        )> = sqlx::query_as(
            "SELECT company, domain, country, industry, employees, technologies, esp_hypotheses \
             FROM sales_accounts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(request.account_id)
        .bind(&request.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| StrategistError::Database(e.to_string()))?;
        let (company, domain, country, industry, employees, technologies, esp_hypotheses) =
            account_row.ok_or_else(|| {
                StrategistError::NotFound(format!("account {}", request.account_id))
            })?;

        let contact_row: Option<(
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT full_name, job_title, persona, country, timezone, language \
             FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(request.contact_id)
        .bind(&request.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| StrategistError::Database(e.to_string()))?;
        let (full_name, job_title, persona, contact_country, timezone, contact_language) =
            contact_row.ok_or_else(|| {
                StrategistError::NotFound(format!("contact {}", request.contact_id))
            })?;

        let signal_rows: Vec<(
            String,
            f64,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<Uuid>,
            serde_json::Value,
        )> = sqlx::query_as(
            "SELECT signal_type, strength, observed_at, expires_at, evidence_id, payload \
             FROM sales_signals WHERE tenant_id = $1 AND account_id = $2 \
             ORDER BY strength DESC LIMIT $3",
        )
        .bind(&request.tenant_id)
        .bind(request.account_id)
        .bind(MAX_SIGNALS_CONSIDERED as i64)
        .fetch_all(&self.db)
        .await
        .map_err(|e| StrategistError::Database(e.to_string()))?;

        let evidence_rows: Vec<(
            Uuid,
            String,
            f64,
            String,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            "SELECT id, proposition, confidence, source_kind, observed_at, expires_at \
             FROM sales_evidence WHERE tenant_id = $1 \
               AND (account_id = $2 OR contact_id = $3) \
             ORDER BY confidence DESC LIMIT 50",
        )
        .bind(&request.tenant_id)
        .bind(request.account_id)
        .bind(request.contact_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| StrategistError::Database(e.to_string()))?;

        let enrichment_rows: Vec<(String, String, serde_json::Value, f64, Option<Uuid>)> =
            sqlx::query_as(
                "SELECT provider, field, value, confidence, evidence_id \
             FROM sales_enrichment_facts WHERE tenant_id = $1 AND subject_type = 'account' \
               AND subject_id = $2 AND field IN ('technologies', 'email_provider')",
            )
            .bind(&request.tenant_id)
            .bind(request.account_id)
            .fetch_all(&self.db)
            .await
            .map_err(|e| StrategistError::Database(e.to_string()))?;

        let mut touches = Vec::new();
        if let Some(enrollment_id) = request.enrollment_id {
            let touch_rows: Vec<(String, String, Option<DateTime<Utc>>, String)> = sqlx::query_as(
                "SELECT attempt_kind, state, executed_at, variant \
                 FROM sales_step_executions WHERE enrollment_id = $1 \
                 ORDER BY created_at DESC LIMIT 25",
            )
            .bind(enrollment_id)
            .fetch_all(&self.db)
            .await
            .map_err(|e| StrategistError::Database(e.to_string()))?;
            touches = touch_rows
                .into_iter()
                .map(|(attempt_kind, state, executed_at, variant)| TouchContext {
                    attempt_kind,
                    state,
                    executed_at,
                    variant,
                })
                .collect();
        }

        // Reply history is contact-scoped, so it is loaded whether or not the
        // request carries an enrollment id (a contact can reply before a
        // second enrollment exists).
        let reply_rows: Vec<(String, f64, DateTime<Utc>)> = sqlx::query_as(
            "SELECT disposition, confidence, created_at \
             FROM sales_reply_classifications WHERE tenant_id = $1 AND contact_id = $2 \
             ORDER BY created_at DESC LIMIT 25",
        )
        .bind(&request.tenant_id)
        .bind(request.contact_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| StrategistError::Database(e.to_string()))?;
        let replies: Vec<ReplyContext> = reply_rows
            .into_iter()
            .map(|(disposition, confidence, created_at)| ReplyContext {
                disposition,
                confidence: confidence as f32,
                created_at,
            })
            .collect();

        Ok(StrategyInput {
            account: AccountContext {
                company,
                domain,
                country,
                industry,
                employees,
                technologies,
                esp_hypotheses: hypotheses_to_strings(&esp_hypotheses),
            },
            contact: ContactContext {
                full_name,
                job_title,
                persona,
                country: contact_country,
                timezone,
                language: contact_language,
            },
            signals: signal_rows
                .into_iter()
                .map(
                    |(signal_type, strength, observed_at, expires_at, evidence_id, payload)| {
                        SignalContext {
                            signal_type,
                            strength: strength as f32,
                            observed_at,
                            expires_at,
                            evidence_id,
                            payload,
                        }
                    },
                )
                .collect(),
            evidence: evidence_rows
                .into_iter()
                .map(
                    |(id, proposition, confidence, source_kind, observed_at, expires_at)| {
                        EvidenceContext {
                            id,
                            proposition,
                            confidence: confidence as f32,
                            source_kind,
                            observed_at,
                            expires_at,
                        }
                    },
                )
                .collect(),
            previous_touches: touches,
            reply_history: replies,
            stack_hypothesis: enrichment_rows
                .into_iter()
                .map(
                    |(provider, field, value, confidence, evidence_id)| StackHypothesis {
                        field,
                        value: json_value_to_string(&value),
                        provider,
                        confidence: confidence as f32,
                        evidence_id,
                    },
                )
                .collect(),
            offer: request.offer.clone(),
            experiment_arm: request.experiment_arm.clone(),
            language: request.language.clone(),
            now: request.now,
            knowledge: self.knowledge.clone(),
        })
    }

    /// Load and compose in one step.
    pub async fn build(
        &self,
        request: &StrategyRequest,
    ) -> Result<MessageStrategy, StrategistError> {
        let input = self.load_input(request).await?;
        Ok(compose_strategy(&input))
    }

    /// Validate a strategy against this builder's knowledge base.
    pub fn validate(&self, strategy: &MessageStrategy) -> StrategyValidation {
        validate_strategy(strategy, &self.knowledge)
    }

    /// Validate + render with a caller-supplied prose writer.
    pub fn render(
        &self,
        strategy: &MessageStrategy,
        writer: &dyn ProseWriter,
    ) -> Result<RenderedStrategy, RenderRejection> {
        render_cold_email(strategy, writer, &self.knowledge)
    }
}

fn hypotheses_to_strings(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| match item {
                serde_json::Value::String(text) => text.clone(),
                other => other
                    .get("proposition")
                    .or_else(|| other.get("statement"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
            .filter(|text| !text.trim().is_empty())
            .collect(),
        serde_json::Value::String(text) => vec![text.clone()],
        _ => Vec::new(),
    }
}

fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn evidence(id: u128, proposition: &str, confidence: f32) -> EvidenceContext {
        EvidenceContext {
            id: uuid(id),
            proposition: proposition.into(),
            confidence,
            source_kind: "http_fetch".into(),
            observed_at: Utc::now(),
            expires_at: None,
        }
    }

    fn input_with(evidence_rows: Vec<EvidenceContext>) -> StrategyInput {
        StrategyInput {
            account: AccountContext {
                company: "Acme".into(),
                domain: "acme.com".into(),
                industry: Some("SaaS".into()),
                ..AccountContext::default()
            },
            contact: ContactContext {
                full_name: "Ada".into(),
                job_title: Some("CTO".into()),
                language: Some("en".into()),
                ..ContactContext::default()
            },
            evidence: evidence_rows,
            offer: "Growth plan for high-volume senders".into(),
            now: Some(Utc::now()),
            knowledge: SalesKnowledgeBase::canonical(),
            ..StrategyInput::default()
        }
    }

    fn knowledge() -> SalesKnowledgeBase {
        SalesKnowledgeBase::canonical()
    }

    // ── Grounding / omission ────────────────────────────────────────────

    #[test]
    fn unevidenced_observed_fact_is_omitted_from_rendered_output() {
        let mut strategy = compose_strategy(&input_with(vec![]));
        assert!(strategy.observed_fact.is_none());
        // Inject an unevidenced fact the way a misbehaving model would.
        strategy.observed_fact = Some(ObservedFact {
            statement: "Your team is migrating to a new ESP next quarter.".into(),
            evidence_id: Uuid::nil(),
            confidence: 0.9,
        });
        let rendered = render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge())
            .expect("render without the unevidenced fact");
        assert!(rendered.observed_fact.is_none());
        assert!(!rendered.body.contains("migrating to a new ESP"));
        assert!(rendered.omitted.iter().any(|violation| matches!(
            violation,
            StrategyViolation::ObservedFactWithoutEvidence { .. }
        )));
    }

    #[test]
    fn evidence_backed_observed_fact_survives() {
        let input = input_with(vec![evidence(7, "Acme uses SendGrid for receipts.", 0.9)]);
        let strategy = compose_strategy(&input);
        let rendered = render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge())
            .expect("render");
        assert_eq!(
            rendered.observed_fact.as_deref(),
            Some("Acme uses SendGrid for receipts.")
        );
        assert!(rendered.omitted.is_empty());
    }

    #[test]
    fn unbacked_proof_point_is_omitted() {
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.proof_point = Some(ProofPoint {
            statement: "We are the market leader.".into(),
            evidence_id: None,
            knowledge_fact_id: Some("KB-DOES-NOT-EXIST".into()),
        });
        let rendered =
            render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge()).unwrap();
        assert!(rendered.proof_point.is_none());
        assert!(rendered
            .omitted
            .iter()
            .any(|violation| matches!(violation, StrategyViolation::ProofPointUnbacked { .. })));
    }

    #[test]
    fn proof_point_with_verified_knowledge_fact_survives_and_expired_does_not() {
        let kb = knowledge();
        let fact = kb
            .external_copy_facts()
            .first()
            .map(|fact| (fact.id.clone(), fact.claim.clone()))
            .expect("canonical base has external-copy facts");
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.proof_point = Some(ProofPoint {
            statement: fact.1.clone(),
            evidence_id: None,
            knowledge_fact_id: Some(fact.0.clone()),
        });
        let rendered = render_cold_email(&strategy, &TemplateProseWriter::new(), &kb).unwrap();
        assert!(rendered.proof_point.is_some());

        // Expired facts never back a proof point.
        let expired = SalesKnowledgeBase::from_facts(vec![crate::knowledge::SalesKnowledgeFact {
            id: "KB-EXPIRED".into(),
            claim: "Old capability.".into(),
            status: crate::knowledge::KnowledgeStatus::Verified,
            valid_from: Utc::now() - chrono::Duration::days(400),
            valid_until: Some(Utc::now() - chrono::Duration::days(1)),
            source: KnowledgeSource::ProductDocs,
            allowed_in_external_copy: true,
        }]);
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.proof_point = Some(ProofPoint {
            statement: "Old capability.".into(),
            evidence_id: None,
            knowledge_fact_id: Some("KB-EXPIRED".into()),
        });
        let rendered = render_cold_email(&strategy, &TemplateProseWriter::new(), &expired).unwrap();
        assert!(rendered.proof_point.is_none());
    }

    #[test]
    fn unsupported_value_prop_is_refused_with_reason() {
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.value_prop = "We support SSO for enterprise customers.".into();
        let error = render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge())
            .expect_err("SSO promise must be refused");
        match error {
            RenderRejection::UnsupportedClaim {
                capability, reason, ..
            } => {
                assert_eq!(capability, "sso");
                assert!(!reason.is_empty());
            }
            other => panic!("expected UnsupportedClaim, got {other:?}"),
        }
    }

    // ── Fake personalization ────────────────────────────────────────────

    #[test]
    fn banned_fake_personalization_patterns_are_rejected_individually() {
        for pattern in BANNED_FAKE_PERSONALIZATION_PATTERNS {
            let mut strategy = compose_strategy(&input_with(vec![]));
            strategy.value_prop = format!("{} and wanted to reach out.", pattern);
            let error = render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge());
            match error {
                Err(RenderRejection::FakePersonalization { pattern: got, .. }) => {
                    assert_eq!(got, *pattern, "pattern {pattern:?} must be reported");
                }
                Err(other) => panic!("pattern {pattern:?} produced {other:?}"),
                Ok(_) => panic!("pattern {pattern:?} must be rejected"),
            }
        }
    }

    #[test]
    fn noticed_you_use_requires_matching_evidence() {
        // No evidence: banned.
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.value_prop = "I noticed you use SendGrid.".into();
        assert!(matches!(
            render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge()),
            Err(RenderRejection::FakePersonalization { .. })
        ));

        // Evidence naming the technology: allowed.
        let mut strategy = compose_strategy(&input_with(vec![evidence(
            11,
            "Acme uses SendGrid for transactional email.",
            0.95,
        )]));
        strategy.value_prop = "I noticed you use SendGrid, which many teams outgrow.".into();
        let rendered = render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge())
            .expect("evidence-backed technology mention is allowed");
        assert!(rendered.body.contains("SendGrid"));

        // Evidence exists but names a DIFFERENT technology: still banned.
        let mut strategy = compose_strategy(&input_with(vec![evidence(
            12,
            "Acme uses Postmark for transactional email.",
            0.95,
        )]));
        strategy.value_prop = "I noticed you use SendGrid.".into();
        assert!(matches!(
            render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge()),
            Err(RenderRejection::FakePersonalization { .. })
        ));
    }

    // ── Composition shape ───────────────────────────────────────────────

    #[test]
    fn composition_picks_one_of_each_part() {
        let input = input_with(vec![
            evidence(1, "Acme raised a Series B.", 0.6),
            evidence(2, "Acme uses SendGrid.", 0.9),
        ]);
        let strategy = compose_strategy(&input);
        assert_eq!(
            strategy.observed_fact.as_ref().map(|f| f.evidence_id),
            Some(uuid(2)),
            "highest-confidence evidence is the observed fact"
        );
        assert!(!strategy.problem_hypothesis.is_empty());
        assert!(!strategy.value_prop.is_empty());
        assert!(strategy.proof_point.is_some());
        assert_eq!(strategy.cta, "Would a 15-minute call next week be useful?");
        assert_eq!(strategy.tone, Tone::Direct);
        assert_eq!(strategy.language, "en");
    }

    #[test]
    fn tone_follows_persona_and_reply_history() {
        let mut input = input_with(vec![]);
        input.contact.job_title = Some("Software Engineer".into());
        assert_eq!(compose_strategy(&input).tone, Tone::Technical);
        input.reply_history.push(ReplyContext {
            disposition: "meeting_request".into(),
            confidence: 0.9,
            created_at: Utc::now(),
        });
        assert_eq!(compose_strategy(&input).tone, Tone::Warm);
        input.contact.persona = Some("Executive".into());
        assert_eq!(
            compose_strategy(&input).tone,
            Tone::Warm,
            "reply history wins"
        );
    }

    #[test]
    fn cta_is_low_friction_and_localised() {
        let mut input = input_with(vec![]);
        input.language = Some("et".into());
        let strategy = compose_strategy(&input);
        assert!(strategy.cta.contains("15-minutiline"));
        assert_eq!(strategy.language, "et");
        let writer = TemplateProseWriter::new();
        let rendered = render_cold_email(&strategy, &writer, &knowledge()).unwrap();
        assert!(rendered.body.contains("Tere"));
    }

    // ── Hostile input ───────────────────────────────────────────────────

    #[test]
    fn no_evidence_at_all_still_renders_without_personalization() {
        let strategy = compose_strategy(&input_with(vec![]));
        let rendered = render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge())
            .expect("cold copy can render without any observation");
        assert!(rendered.observed_fact.is_none());
        assert!(!rendered.problem_value.is_empty());
        assert!(!rendered.cta.is_empty());
    }

    #[test]
    fn thousand_signals_do_not_panic_or_explode() {
        let mut input = input_with(vec![]);
        input.signals = (0..1000)
            .map(|i| SignalContext {
                signal_type: format!("signal_{}", i % 7),
                strength: (i as f32 % 100.0) / 100.0,
                observed_at: Utc::now(),
                expires_at: None,
                evidence_id: None,
                payload: serde_json::json!({}),
            })
            .collect();
        let strategy = compose_strategy(&input);
        let rendered = render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge())
            .expect("hostile signal volume must not panic or refuse");
        assert!(!rendered.body.is_empty());
    }

    #[test]
    fn contradictory_persona_data_does_not_panic() {
        let mut input = input_with(vec![]);
        input.contact.persona = Some("C-Level Executive".into());
        input.contact.job_title = Some("Intern".into());
        input.contact.language = Some("".into());
        let strategy = compose_strategy(&input);
        assert_eq!(strategy.language, "en", "empty language falls back to en");
        assert_eq!(strategy.tone, Tone::Direct);
        assert!(render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge()).is_ok());
    }

    #[test]
    fn oversized_and_broken_fields_are_truncated_not_panicked() {
        let huge = "x".repeat(1024 * 1024);
        let mut input = input_with(vec![evidence(1, &huge, 0.9)]);
        input.contact.language = Some(huge.clone());
        input.offer = huge.clone();
        let strategy = compose_strategy(&input);
        assert!(
            strategy
                .observed_fact
                .as_ref()
                .unwrap()
                .statement
                .chars()
                .count()
                <= MAX_FIELD_CHARS + 1
        );
        assert!(strategy.language.chars().count() <= 36);
        assert!(strategy.offer.chars().count() <= MAX_FIELD_CHARS + 1);
        assert!(render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge()).is_ok());

        // NaN / infinite confidence is dropped by validation.
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.observed_fact = Some(ObservedFact {
            statement: "Broken confidence".into(),
            evidence_id: uuid(1),
            confidence: f32::NAN,
        });
        let validation = validate_strategy(&strategy, &knowledge());
        assert!(validation.strategy.observed_fact.is_none());
        assert!(validation.violations.iter().any(|violation| matches!(
            violation,
            StrategyViolation::ObservedFactInvalidConfidence { .. }
        )));
    }

    #[test]
    fn high_pressure_cta_is_refused() {
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.cta = "Buy now, limited time offer!".into();
        assert!(matches!(
            render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge()),
            Err(RenderRejection::HighPressureCta { .. })
        ));
    }

    #[test]
    fn empty_value_prop_is_refused() {
        let mut strategy = compose_strategy(&input_with(vec![]));
        strategy.value_prop = "   ".into();
        assert!(matches!(
            render_cold_email(&strategy, &TemplateProseWriter::new(), &knowledge()),
            Err(RenderRejection::MissingRequiredPart { .. })
        ));
    }

    #[test]
    fn template_writer_is_deterministic() {
        let strategy = compose_strategy(&input_with(vec![evidence(1, "Acme uses SendGrid.", 0.9)]));
        let writer = TemplateProseWriter::new();
        let first = render_cold_email(&strategy, &writer, &knowledge()).unwrap();
        let second = render_cold_email(&strategy, &writer, &knowledge()).unwrap();
        assert_eq!(first.body, second.body);
        assert_eq!(first.subject, second.subject);
    }
}
