//! §8 — explainable multi-dimensional opportunity scoring.
//!
//! Replaces the single weighted 0-100 lead score with a feature vector whose
//! every dimension is stored in `sales_scores` and whose every point of the
//! composite total is explained by a signed, human-readable reason code.
//!
//! # Composite
//!
//! Each of the ten positive dimensions is measured `0..=100` (higher is
//! better). Its integer point contribution is `round(weight × dimension)`.
//! The risk dimension is a penalty: `−round(WEIGHT_RISK_PENALTY × risk)`.
//! `total = clamp(Σ contributions, 0, 100)`, with an explicit signed
//! adjustment code recorded whenever clamping changes the value.
//!
//! | Dimension | Weight | Meaning |
//! |---|---|---|
//! | `account_fit` | 0.18 | ICP segment, employee band, industry |
//! | `persona_fit` | 0.12 | job title / department / seniority |
//! | `need_fit` | 0.13 | vertical + pain-change signals |
//! | `intent` | 0.08 | verified intent signals (NOT opens) |
//! | `timing` | 0.11 | base account fit + decayed signal urgency |
//! | `email_stack_fit` | 0.10 | detected ESP / deliverability posture |
//! | `eu_residency_fit` | 0.05 | EEA data-residency relevance |
//! | `reachability` | 0.10 | verified contact points |
//! | `evidence_quality` | 0.05 | evidence count, mean confidence, freshness |
//! | `legal_contactability` | 0.08 | jurisdiction-policy verdict |
//! | `risk` (penalty) | 0.20 | complaints, negative replies, frequency pressure |
//!
//! # Reason-code reconciliation rule
//!
//! Every string in `reason_codes` starts with an explicit sign and an integer
//! number of points (`"+18 account fit: …"`, `"-4 risk: …"`), including the
//! clamp adjustment and any `"+0 …"` sanitation notes. Therefore
//!
//! ```text
//! Σ reason_code_points(reason_codes) == total   (exactly, in integer points)
//! ```
//!
//! and [`reconcile_reason_codes`] recovers that sum. Tests assert the identity
//! within [`REASON_CODE_RECONCILIATION_EPSILON`].
//!
//! # Decision objective
//!
//! The objective is **expected incremental gross profit**, not the composite
//! total, and it never depends on opens or clicks.
//!
//! ```text
//! EV = P(qualified reply) × P(meeting | qualified reply) × P(win | meeting)
//!      × expected LTV contribution
//!      − outreach cost
//!      − reputation-risk penalty
//!      − compliance-risk penalty
//! ```
//!
//! # Never opens
//!
//! `OutcomeFeatures::opens` is carried so callers can record it, but it is
//! **not read anywhere in this module**. An account with 10 000 opens and
//! nothing else scores identically to the same account with none. Opens are
//! too weak a signal under Apple Mail Privacy Protection to optimize against.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::signals::{combined_urgency, SignalObservation};
use crate::types::{ContactDecision, OpportunityScore, SalesError};

/// Version stamped into `sales_scores.scoring_version`. A decision can be
/// replayed against the exact scoring version that produced it; bump this on
/// any weight, formula or reason-code change.
pub const SCORING_VERSION: &str = "sales-score-v2.0.0";

/// Composite total lower bound.
pub const TOTAL_MIN: f32 = 0.0;
/// Composite total upper bound.
pub const TOTAL_MAX: f32 = 100.0;

/// Tolerance for the documented reason-code reconciliation identity. Sums are
/// integer-valued, so the observed error is exactly 0; the epsilon exists so
/// a future fractional reason-code formatter cannot silently break the test.
pub const REASON_CODE_RECONCILIATION_EPSILON: f32 = 0.01;

// Weights. The positive weights sum to exactly 1.0, so a perfect account with
// zero risk reaches 100; the risk penalty can subtract up to 15 points.
pub const WEIGHT_ACCOUNT_FIT: f32 = 0.18;
pub const WEIGHT_PERSONA_FIT: f32 = 0.12;
pub const WEIGHT_NEED_FIT: f32 = 0.13;
pub const WEIGHT_INTENT: f32 = 0.08;
pub const WEIGHT_TIMING: f32 = 0.11;
pub const WEIGHT_EMAIL_STACK_FIT: f32 = 0.10;
pub const WEIGHT_EU_RESIDENCY_FIT: f32 = 0.05;
pub const WEIGHT_REACHABILITY: f32 = 0.10;
pub const WEIGHT_EVIDENCE_QUALITY: f32 = 0.05;
pub const WEIGHT_LEGAL_CONTACTABILITY: f32 = 0.08;
pub const WEIGHT_RISK_PENALTY: f32 = 0.20;

/// Verticals ApexMail's offer is built for. Matching is a documented
/// case-insensitive substring test.
pub const ICP_VERTICAL_KEYWORDS: &[&str] = &[
    "saas",
    "software",
    "ecommerce",
    "e-commerce",
    "marketplace",
    "fintech",
    "financial",
    "education",
    "edtech",
    "media",
    "publisher",
    "travel",
    "retail",
    "healthtech",
    "insurance",
    "telecom",
    "logistics",
    "crypto",
    "gaming",
];

/// Signal types that indicate active email/engineering pain (raise `need_fit`
/// in addition to `timing`).
pub const PAIN_SIGNAL_TYPES: &[&str] = &[
    "new_engineering_jobs",
    "new_security_jobs",
    "email_stack_change",
    "pricing_change",
    "funding",
    "product_launch",
    "security_compliance_page_change",
];

// ---------------------------------------------------------------------------
// Feature vector
// ---------------------------------------------------------------------------

/// Strength of the account's match to the tenant's ICP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SegmentMatch {
    Strong,
    Partial,
    #[default]
    Unknown,
    Weak,
}

impl SegmentMatch {
    pub fn label(self) -> &'static str {
        match self {
            Self::Strong => "strong ICP segment match",
            Self::Partial => "partial ICP segment match",
            Self::Weak => "weak ICP segment match",
            Self::Unknown => "unknown ICP segment",
        }
    }
}

/// EEA / data-residency relevance of the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EeaRelevance {
    InScope,
    OutOfScope,
    #[default]
    Unknown,
}

/// Detected email-stack facts (from `signals::email_stack` evidence, never
/// asserted as facts — the confidence travels with them).
#[derive(Debug, Clone, Default)]
pub struct EmailStackFeatures {
    pub providers: Vec<String>,
    /// Confidence of the strongest vendor hypothesis, `0.0..=1.0`.
    pub confidence: f32,
    /// Deliverability configuration quality, `0.0..=1.0` (see
    /// `signals::email_stack::deliverability_quality`).
    pub authentication_quality: f32,
}

/// Persona features from `sales_contacts.job_title` / `department` /
/// `seniority`.
#[derive(Debug, Clone, Default)]
pub struct PersonaFeatures {
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub seniority: Option<String>,
}

/// Reachability features from `sales_contact_points`.
#[derive(Debug, Clone, Default)]
pub struct ReachabilityFeatures {
    pub verified_contact_points: u32,
    /// Best verification confidence, `0.0..=1.0`.
    pub best_confidence: f32,
}

/// Evidence features aggregated from `sales_evidence`.
#[derive(Debug, Clone, Default)]
pub struct EvidenceFeatures {
    pub count: u32,
    /// Mean confidence, `0.0..=1.0`.
    pub mean_confidence: f32,
    /// Age of the newest observation in days (None when no evidence).
    pub newest_age_days: Option<f32>,
}

/// Risk inputs: delivery/complaint history, negative replies and frequency
/// pressure. Higher is worse.
#[derive(Debug, Clone, Default)]
pub struct RiskFeatures {
    pub complaints: u32,
    pub negative_replies: u32,
    /// `0.0..=1.0` budget pressure (how close the account is to its
    /// frequency cap).
    pub frequency_pressure: f32,
}

/// Previous outcome counts from `sales_outcomes`.
///
/// `opens` and `clicks` are recorded for completeness and are explicitly
/// ignored by every scoring formula in this module.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutcomeFeatures {
    pub delivered: u32,
    /// Recorded, never scored.
    pub opens: u32,
    /// Recorded, never scored (clicks are secondary diagnostics only).
    pub clicks: u32,
    pub replies: u32,
    pub positive_replies: u32,
    pub meetings_booked: u32,
    pub trials: u32,
    pub paid_subscriptions: u32,
    pub bounces: u32,
    pub complaints: u32,
    pub unsubscribes: u32,
}

/// Economic inputs to the expected-value objective, in EUR.
#[derive(Debug, Clone, Copy, Default)]
pub struct EconomicsFeatures {
    /// Expected LTV contribution of a won deal. Must be finite and
    /// non-negative; hostile values are sanitised with a recorded reason.
    pub expected_ltv_contribution_eur: f64,
    /// Fully-loaded cost of the outreach attempt(s).
    pub outreach_cost_eur: f64,
    /// Explicit reputation-risk penalty; when zero the scorer derives one
    /// from the risk dimension.
    pub reputation_risk_penalty_eur: f64,
    /// Explicit compliance-risk penalty; a `Prohibited` legal verdict floors
    /// this at a fraction of LTV.
    pub compliance_risk_penalty_eur: f64,
}

/// The complete input feature vector. Every field a dimension needs is here,
/// so [`score`] is a pure function with no database access.
#[derive(Debug, Clone)]
pub struct ScoreFeatures {
    /// Evaluation instant; drives signal decay and is the caller's clock so
    /// the function stays deterministic.
    pub now: DateTime<Utc>,
    pub segment_match: SegmentMatch,
    pub employees: Option<i64>,
    pub industry: Option<String>,
    pub ideal_employees_min: i64,
    pub ideal_employees_max: i64,
    pub email_stack: EmailStackFeatures,
    pub eea_relevance: EeaRelevance,
    /// Verified intent signals. Open/click outcomes must never be added here.
    pub intent_signals: Vec<SignalObservation>,
    pub persona: PersonaFeatures,
    pub reachability: ReachabilityFeatures,
    pub evidence: EvidenceFeatures,
    pub legal: ContactDecision,
    pub risk: RiskFeatures,
    pub outcomes: OutcomeFeatures,
    pub economics: EconomicsFeatures,
}

impl Default for ScoreFeatures {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            segment_match: SegmentMatch::Unknown,
            employees: None,
            industry: None,
            ideal_employees_min: 50,
            ideal_employees_max: 500,
            email_stack: EmailStackFeatures::default(),
            eea_relevance: EeaRelevance::Unknown,
            intent_signals: Vec::new(),
            persona: PersonaFeatures::default(),
            reachability: ReachabilityFeatures::default(),
            evidence: EvidenceFeatures::default(),
            legal: ContactDecision::ApprovalRequired,
            risk: RiskFeatures::default(),
            outcomes: OutcomeFeatures::default(),
            economics: EconomicsFeatures::default(),
        }
    }
}

/// Strict validation for callers that would rather reject hostile features
/// than let [`score`] sanitise them. Returns the first problem found.
pub fn validate_features(features: &ScoreFeatures) -> Result<(), SalesError> {
    if let Some(employees) = features.employees {
        if employees < 0 {
            return Err(SalesError::InvalidInput(format!(
                "employees must be >= 0, got {employees}"
            )));
        }
    }
    if features.ideal_employees_min > features.ideal_employees_max {
        return Err(SalesError::InvalidInput(format!(
            "ideal employee band inverted: {} > {}",
            features.ideal_employees_min, features.ideal_employees_max
        )));
    }
    check_unit("email_stack.confidence", features.email_stack.confidence)?;
    check_unit(
        "email_stack.authentication_quality",
        features.email_stack.authentication_quality,
    )?;
    check_unit(
        "reachability.best_confidence",
        features.reachability.best_confidence,
    )?;
    check_unit(
        "evidence.mean_confidence",
        features.evidence.mean_confidence,
    )?;
    if let Some(age) = features.evidence.newest_age_days {
        if !age.is_finite() || age < 0.0 {
            return Err(SalesError::InvalidInput(format!(
                "evidence.newest_age_days must be finite and >= 0, got {age}"
            )));
        }
    }
    check_unit("risk.frequency_pressure", features.risk.frequency_pressure)?;
    for (index, observation) in features.intent_signals.iter().enumerate() {
        if observation.signal_type.trim().is_empty() {
            return Err(SalesError::InvalidInput(format!(
                "intent_signals[{index}].signal_type must not be empty"
            )));
        }
        if !observation.strength.is_finite() || !(0.0..=1.0).contains(&observation.strength) {
            return Err(SalesError::InvalidInput(format!(
                "intent_signals[{index}].strength must be in 0.0..=1.0, got {}",
                observation.strength
            )));
        }
    }
    for (label, value) in [
        (
            "economics.expected_ltv_contribution_eur",
            features.economics.expected_ltv_contribution_eur,
        ),
        (
            "economics.outreach_cost_eur",
            features.economics.outreach_cost_eur,
        ),
        (
            "economics.reputation_risk_penalty_eur",
            features.economics.reputation_risk_penalty_eur,
        ),
        (
            "economics.compliance_risk_penalty_eur",
            features.economics.compliance_risk_penalty_eur,
        ),
    ] {
        if !value.is_finite() || value < 0.0 {
            return Err(SalesError::InvalidInput(format!(
                "{label} must be finite and >= 0, got {value}"
            )));
        }
    }
    Ok(())
}

fn check_unit(label: &str, value: f32) -> Result<(), SalesError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(SalesError::InvalidInput(format!(
            "{label} must be in 0.0..=1.0, got {value}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dimensions (pure helpers; scores may exceed 100 only until `score` bounds
// them, which is recorded as a reason code)
// ---------------------------------------------------------------------------

fn matches_icp_vertical(industry: Option<&str>) -> bool {
    industry
        .map(|raw| {
            let lower = raw.to_ascii_lowercase();
            ICP_VERTICAL_KEYWORDS
                .iter()
                .any(|keyword| lower.contains(keyword))
        })
        .unwrap_or(false)
}

/// Account fit: ICP segment + employee band + industry presence.
/// Raw range with valid inputs is `20.0..=100.0`.
pub fn account_fit_dimension(
    segment_match: SegmentMatch,
    employees: Option<i64>,
    industry: Option<&str>,
    ideal_min: i64,
    ideal_max: i64,
) -> f32 {
    let mut score = 40.0f32;
    score += match segment_match {
        SegmentMatch::Strong => 35.0,
        SegmentMatch::Partial => 18.0,
        SegmentMatch::Weak => -10.0,
        SegmentMatch::Unknown => 0.0,
    };
    if let Some(employees) = employees {
        let (low, high) = if ideal_min <= ideal_max {
            (ideal_min, ideal_max)
        } else {
            (ideal_max, ideal_min)
        };
        let half_low = (low / 2).max(1);
        let double_high = high.saturating_mul(2);
        if employees >= low && employees <= high {
            score += 20.0;
        } else if employees >= half_low && employees <= double_high {
            score += 8.0;
        } else {
            score -= 10.0;
        }
    }
    if industry
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        score += 5.0;
    }
    score
}

fn seniority_rank(value: &str) -> u8 {
    let lower = value.to_ascii_lowercase();
    const RANK_4: &[&str] = &[
        "c-level",
        "c-suite",
        "ceo",
        "cto",
        "cfo",
        "coo",
        "cmo",
        "cro",
        "cio",
        "ciso",
        "founder",
        "co-founder",
        "owner",
        "president",
        "partner",
        "chief",
        "vice president",
        "vp",
        "executive",
    ];
    const RANK_3: &[&str] = &["head", "director"];
    const RANK_2: &[&str] = &["manager", "lead"];
    const RANK_1: &[&str] = &[
        "senior",
        "staff",
        "principal",
        "specialist",
        "engineer",
        "analyst",
    ];
    if RANK_4.iter().any(|needle| lower.contains(needle)) {
        4
    } else if RANK_3.iter().any(|needle| lower.contains(needle)) {
        3
    } else if RANK_2.iter().any(|needle| lower.contains(needle)) {
        2
    } else if RANK_1.iter().any(|needle| lower.contains(needle)) {
        1
    } else {
        0
    }
}

fn title_rank(title: &str) -> u8 {
    seniority_rank(title)
}

/// Persona fit: title, seniority and department. Raw range with valid inputs
/// is `20.0..=100.0`.
pub fn persona_fit_dimension(persona: &PersonaFeatures) -> f32 {
    let seniority = persona
        .seniority
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(seniority_rank);
    let title = persona
        .job_title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(title_rank);
    let rank = seniority.into_iter().chain(title).max().unwrap_or(0);
    let base = match rank {
        4 => 85.0,
        3 => 70.0,
        2 => 55.0,
        1 => 40.0,
        _ => 20.0,
    };
    let department = persona
        .department
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let department_bonus = if [
        "engineering",
        "security",
        "infrastructure",
        "platform",
        "devops",
        "operations",
        "product",
        "data",
    ]
    .iter()
    .any(|needle| department.contains(needle))
    {
        10.0
    } else if ["marketing", "sales", "revenue", "growth", "finance"]
        .iter()
        .any(|needle| department.contains(needle))
    {
        5.0
    } else {
        0.0
    };
    let title_bonus = if persona
        .job_title
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        5.0
    } else {
        0.0
    };
    base + department_bonus + title_bonus
}

/// Need fit: vertical match plus decayed pain-change signals.
pub fn need_fit_dimension(
    industry: Option<&str>,
    signals: &[SignalObservation],
    now: DateTime<Utc>,
) -> f32 {
    let mut score = 45.0f32;
    if matches_icp_vertical(industry) {
        score += 25.0;
    }
    let pain: Vec<SignalObservation> = signals
        .iter()
        .filter(|observation| PAIN_SIGNAL_TYPES.contains(&observation.signal_type.as_str()))
        .cloned()
        .collect();
    score += 30.0 * combined_urgency(&pain, now);
    score
}

/// Verified intent: strongest decayed urgency plus a small breadth bonus
/// (capped at five extra signals, so a 10 000-signal account cannot dominate
/// by count alone). Returns 0.0 with no signals and decays to 0.0 as signals
/// go stale.
pub fn intent_dimension(signals: &[SignalObservation], now: DateTime<Utc>) -> f32 {
    if signals.is_empty() {
        return 0.0;
    }
    let strongest = signals
        .iter()
        .map(|observation| combined_urgency(std::slice::from_ref(observation), now))
        .fold(0.0f32, f32::max);
    if strongest <= f32::EPSILON {
        return 0.0;
    }
    let breadth_bonus = 8.0 * (signals.len().saturating_sub(1).min(5) as f32);
    (70.0 + breadth_bonus) * strongest
}

/// Timing: how likely the account is to buy *now*. Half base account fit
/// (an account that fits is always somewhat timely) plus 55 points scaled by
/// the noisy-OR urgency of all signals. A stale signal decays toward zero and
/// therefore does not raise timing above the no-signal baseline.
pub fn timing_dimension(
    base_account_fit: f32,
    signals: &[SignalObservation],
    now: DateTime<Utc>,
) -> f32 {
    let base = clamp_unit100(base_account_fit);
    0.5 * base + 55.0 * combined_urgency(signals, now)
}

/// Email-stack fit: ApexMail sells email infrastructure expertise, so a
/// detected transactional/bulk vendor is a fit signal, and a weak
/// authentication posture is an opportunity.
pub fn email_stack_fit_dimension(stack: &EmailStackFeatures) -> f32 {
    if stack.providers.is_empty() {
        return 20.0;
    }
    let confidence = clamp_unit01(stack.confidence);
    let auth = clamp_unit01(stack.authentication_quality);
    40.0 + 45.0 * confidence + 15.0 * (1.0 - auth)
}

/// EU/EEA data-residency fit.
pub fn eu_residency_fit_dimension(relevance: EeaRelevance) -> f32 {
    match relevance {
        EeaRelevance::InScope => 90.0,
        EeaRelevance::Unknown => 50.0,
        EeaRelevance::OutOfScope => 30.0,
    }
}

/// Reachability from verified contact points.
pub fn reachability_dimension(features: &ReachabilityFeatures) -> f32 {
    let confidence = clamp_unit01(features.best_confidence);
    match features.verified_contact_points {
        0 => 0.0,
        1 => 60.0 + 20.0 * confidence,
        2 => 80.0 + 10.0 * confidence,
        _ => 90.0 + 10.0 * confidence,
    }
}

/// Evidence quality: count (capped at 5), mean confidence and freshness.
pub fn evidence_quality_dimension(features: &EvidenceFeatures) -> f32 {
    if features.count == 0 {
        return 0.0;
    }
    let count_part = 40.0 * (features.count.min(5) as f32 / 5.0);
    let confidence_part = 40.0 * clamp_unit01(features.mean_confidence);
    let freshness_part = match features.newest_age_days {
        Some(days) if (0.0..=30.0).contains(&days) => 20.0,
        Some(days) if (0.0..=180.0).contains(&days) => 10.0,
        _ => 0.0,
    };
    count_part + confidence_part + freshness_part
}

/// Legal contactability from the jurisdiction-policy verdict.
pub fn legal_contactability_dimension(legal: ContactDecision) -> f32 {
    match legal {
        ContactDecision::Allowed => 100.0,
        ContactDecision::ApprovalRequired => 45.0,
        ContactDecision::Prohibited => 0.0,
    }
}

/// Risk (higher is worse): complaints, negative replies, unsubscribes,
/// bounces and frequency pressure. Raw value can legitimately exceed 100 for
/// a very bad account; the composite records the clamp.
pub fn risk_dimension(risk: &RiskFeatures, outcomes: &OutcomeFeatures) -> f32 {
    let complaints = risk.complaints.saturating_add(outcomes.complaints);
    let negative = risk.negative_replies.saturating_add(outcomes.unsubscribes);
    let bounces = outcomes.bounces;
    let pressure = clamp_unit01(risk.frequency_pressure);
    40.0 * (complaints.min(2) as f32)
        + 15.0 * (negative.min(3) as f32)
        + 5.0 * (bounces.min(3) as f32)
        + 40.0 * pressure
}

fn clamp_unit01(value: f32) -> f32 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn clamp_unit100(value: f32) -> f32 {
    if value.is_finite() {
        value.clamp(0.0, 100.0)
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Probabilities and the EV objective
// ---------------------------------------------------------------------------

fn sanitize_probability(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn sanitize_money(value: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        0.0
    }
}

/// P(qualified reply), from the fit/intent dimensions.
pub fn p_qualified_reply(
    account_fit: f32,
    persona_fit: f32,
    need_fit: f32,
    intent: f32,
    email_stack_fit: f32,
) -> f64 {
    let account = f64::from(clamp_unit100(account_fit)) / 100.0;
    let persona = f64::from(clamp_unit100(persona_fit)) / 100.0;
    let need = f64::from(clamp_unit100(need_fit)) / 100.0;
    let intent = f64::from(clamp_unit100(intent)) / 100.0;
    let stack = f64::from(clamp_unit100(email_stack_fit)) / 100.0;
    (0.01 + 0.22 * intent + 0.12 * persona + 0.08 * account + 0.06 * stack + 0.05 * need)
        .clamp(0.0, 0.75)
}

/// P(meeting | qualified reply), from timing, reachability and evidence.
pub fn p_meeting_given_qualified_reply(
    timing: f32,
    reachability: f32,
    evidence_quality: f32,
) -> f64 {
    let timing = f64::from(clamp_unit100(timing)) / 100.0;
    let reachability = f64::from(clamp_unit100(reachability)) / 100.0;
    let evidence = f64::from(clamp_unit100(evidence_quality)) / 100.0;
    (0.05 + 0.40 * timing + 0.25 * reachability + 0.10 * evidence).clamp(0.0, 0.90)
}

/// P(win | meeting), from account fit, legal posture and risk.
pub fn p_win_given_meeting(account_fit: f32, legal: f32, risk: f32) -> f64 {
    let account = f64::from(clamp_unit100(account_fit)) / 100.0;
    let legal = f64::from(clamp_unit100(legal)) / 100.0;
    let risk = f64::from(clamp_unit100(risk)) / 100.0;
    let risk_factor = (1.0 - 0.5 * risk).clamp(0.0, 1.0);
    ((0.05 + 0.35 * account + 0.10 * legal) * risk_factor).clamp(0.0, 0.90)
}

/// The decision objective: expected incremental gross profit.
///
/// ```text
/// EV = P(qualified reply) × P(meeting | qualified reply) × P(win | meeting)
///      × expected LTV contribution
///      − outreach cost
///      − reputation-risk penalty
///      − compliance-risk penalty
/// ```
///
/// Pure and total: non-finite probabilities become `0.0`, out-of-range
/// probabilities are clamped to `0.0..=1.0`, and negative/non-finite money
/// terms become `0.0`. The result is always finite (a product of fractions
/// with a finite LTV cannot overflow). The objective is **not** the composite
/// total: a prospect with a high meeting probability but no LTV contribution
/// has a strongly negative EV and must never outrank one with real LTV.
pub fn expected_value_eur(
    p_qualified_reply: f64,
    p_meeting_given_qualified_reply: f64,
    p_win_given_meeting: f64,
    expected_ltv_contribution_eur: f64,
    outreach_cost_eur: f64,
    reputation_risk_penalty_eur: f64,
    compliance_risk_penalty_eur: f64,
) -> f64 {
    let probability = sanitize_probability(p_qualified_reply)
        * sanitize_probability(p_meeting_given_qualified_reply)
        * sanitize_probability(p_win_given_meeting);
    let ltv = sanitize_money(expected_ltv_contribution_eur);
    let costs = sanitize_money(outreach_cost_eur)
        + sanitize_money(reputation_risk_penalty_eur)
        + sanitize_money(compliance_risk_penalty_eur);
    let value = probability * ltv - costs;
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

/// Default reputation penalty when the caller supplied none: a fraction of
/// expected LTV proportional to the risk dimension.
pub fn derived_reputation_penalty_eur(risk_dimension: f32, expected_ltv_eur: f64) -> f64 {
    let risk = f64::from(clamp_unit100(risk_dimension)) / 100.0;
    0.002 * sanitize_money(expected_ltv_eur) * risk
}

/// Compliance floor when the legal verdict is `Prohibited`: no expected
/// positive EV can survive a prohibited contact (25% of LTV as the modelled
/// regulatory/reputational cost, on top of any explicit penalty).
pub fn derived_compliance_penalty_eur(legal: ContactDecision, expected_ltv_eur: f64) -> f64 {
    match legal {
        ContactDecision::Prohibited => 0.25 * sanitize_money(expected_ltv_eur),
        ContactDecision::Allowed | ContactDecision::ApprovalRequired => 0.0,
    }
}

// ---------------------------------------------------------------------------
// Reason codes
// ---------------------------------------------------------------------------

/// Parse the signed integer points a reason code starts with. Returns `None`
/// for a code that does not follow the documented format.
pub fn reason_code_points(code: &str) -> Option<i32> {
    let trimmed = code.trim_start();
    let mut chars = trimmed.chars();
    match chars.next() {
        Some('+') | Some('-') => {}
        _ => return None,
    }
    let sign = if trimmed.starts_with('-') { -1 } else { 1 };
    let digits: String = trimmed[1..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i32>().ok().map(|value| sign * value)
}

/// Sum the contributions of a reason-code list. Codes that do not match the
/// documented signed-integer format are skipped (callers/tests should assert
/// none are skipped).
pub fn reconcile_reason_codes(reason_codes: &[String]) -> f32 {
    reason_codes
        .iter()
        .filter_map(|code| reason_code_points(code))
        .sum::<i32>() as f32
}

struct CodeWriter {
    codes: Vec<String>,
    points: i32,
}

impl CodeWriter {
    fn new() -> Self {
        Self {
            codes: Vec::new(),
            points: 0,
        }
    }

    /// Record a signed `+0` sanitation note (never contributes points).
    fn note(&mut self, message: &str) {
        self.codes.push(format!("+0 {message}"));
    }

    /// Sanitize a raw dimension into `0..=100`, recording why when it had to
    /// be clamped, then add `round(weight × dimension)` points.
    fn contribution(&mut self, label: &str, weight: f32, raw: f32, detail: &str) -> i32 {
        let (value, note) = sanitize_dimension(label, raw);
        if let Some(note) = note {
            self.note(&note);
        }
        let points = (weight * value).round() as i32;
        self.points += points;
        self.codes.push(format!("{points:+} {label}: {detail}"));
        points
    }

    /// Same, but the points are a penalty (subtracted).
    fn penalty(&mut self, label: &str, weight: f32, raw: f32, detail: &str) -> i32 {
        let (value, note) = sanitize_dimension(label, raw);
        if let Some(note) = note {
            self.note(&note);
        }
        let points = -((weight * value).round() as i32);
        self.points += points;
        self.codes.push(format!("{points:+} {label}: {detail}"));
        points
    }
}

fn sanitize_dimension(label: &str, raw: f32) -> (f32, Option<String>) {
    if raw.is_nan() {
        return (
            0.0,
            Some(format!("{label} dimension was NaN; treated as 0.0")),
        );
    }
    if raw == f32::INFINITY {
        return (
            100.0,
            Some(format!("{label} dimension was +inf; clamped to 100.0")),
        );
    }
    if raw == f32::NEG_INFINITY {
        return (
            0.0,
            Some(format!("{label} dimension was -inf; clamped to 0.0")),
        );
    }
    if raw < 0.0 {
        return (
            0.0,
            Some(format!(
                "{label} dimension {raw:.2} below range; clamped to 0.0"
            )),
        );
    }
    if raw > 100.0 {
        return (
            100.0,
            Some(format!(
                "{label} dimension {raw:.2} above range; clamped to 100.0"
            )),
        );
    }
    (raw, None)
}

fn clamp01_with_note(label: &str, value: f32, writer: &mut CodeWriter) -> f32 {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        return value;
    }
    let sanitized = clamp_unit01(value);
    writer.note(&format!(
        "{label} input {value} out of range; treated as {sanitized}"
    ));
    sanitized
}

fn sanitize_money_with_note(label: &str, value: f64, writer: &mut CodeWriter) -> f64 {
    if value.is_finite() && value >= 0.0 {
        return value;
    }
    writer.note(&format!(
        "{label} input {value} out of range; treated as 0.0"
    ));
    0.0
}

fn format_employees(employees: Option<i64>, low: i64, high: i64) -> String {
    match employees {
        None => "unknown employees".to_string(),
        Some(count) if count >= low && count <= high => {
            format!("{count} employees (in {low}-{high} band)")
        }
        Some(count) => format!("{count} employees (outside {low}-{high} band)"),
    }
}

// ---------------------------------------------------------------------------
// The scorer
// ---------------------------------------------------------------------------

/// Score one account (and optionally one contact) into an
/// [`OpportunityScore`]. Pure: no database, no clock beyond
/// [`ScoreFeatures::now`], no panics.
///
/// Hostile inputs never produce a NaN or infinite dimension or total: every
/// out-of-range value is clamped and the clamp is recorded as a signed `+0`
/// reason code, so an operator can see exactly what was sanitised.
pub fn score(features: &ScoreFeatures) -> OpportunityScore {
    let mut writer = CodeWriter::new();

    // ---- sanitize the raw inputs, recording every repair -------------------
    let employees = match features.employees {
        Some(value) if value < 0 => {
            writer.note(&format!("employees input {value} < 0; treated as unknown"));
            None
        }
        other => other,
    };
    let stack_confidence = clamp01_with_note(
        "email_stack.confidence",
        features.email_stack.confidence,
        &mut writer,
    );
    let stack_auth = clamp01_with_note(
        "email_stack.authentication_quality",
        features.email_stack.authentication_quality,
        &mut writer,
    );
    let best_confidence = clamp01_with_note(
        "reachability.best_confidence",
        features.reachability.best_confidence,
        &mut writer,
    );
    let mean_confidence = clamp01_with_note(
        "evidence.mean_confidence",
        features.evidence.mean_confidence,
        &mut writer,
    );
    let frequency_pressure = clamp01_with_note(
        "risk.frequency_pressure",
        features.risk.frequency_pressure,
        &mut writer,
    );

    let mut signals: Vec<SignalObservation> = Vec::with_capacity(features.intent_signals.len());
    for observation in &features.intent_signals {
        let mut signal = observation.clone();
        if !signal.strength.is_finite() || !(0.0..=1.0).contains(&signal.strength) {
            let sanitized = clamp_unit01(signal.strength);
            writer.note(&format!(
                "signal `{}` strength {} out of range; treated as {sanitized}",
                signal.signal_type, signal.strength
            ));
            signal.strength = sanitized;
        }
        if signal.signal_type.trim().is_empty() {
            writer.note("signal with empty signal_type ignored for intent/timing");
            continue;
        }
        signals.push(signal);
    }

    let email_stack = EmailStackFeatures {
        providers: features.email_stack.providers.clone(),
        confidence: stack_confidence,
        authentication_quality: stack_auth,
    };
    let reachability = ReachabilityFeatures {
        verified_contact_points: features.reachability.verified_contact_points,
        best_confidence,
    };
    let evidence = EvidenceFeatures {
        count: features.evidence.count,
        mean_confidence,
        newest_age_days: features
            .evidence
            .newest_age_days
            .filter(|days| days.is_finite() && *days >= 0.0),
    };
    let risk = RiskFeatures {
        complaints: features.risk.complaints,
        negative_replies: features.risk.negative_replies,
        frequency_pressure,
    };

    let ltv = sanitize_money_with_note(
        "expected_ltv_contribution_eur",
        features.economics.expected_ltv_contribution_eur,
        &mut writer,
    );
    let outreach_cost = sanitize_money_with_note(
        "outreach_cost_eur",
        features.economics.outreach_cost_eur,
        &mut writer,
    );
    let mut reputation_penalty = sanitize_money_with_note(
        "reputation_risk_penalty_eur",
        features.economics.reputation_risk_penalty_eur,
        &mut writer,
    );
    let mut compliance_penalty = sanitize_money_with_note(
        "compliance_risk_penalty_eur",
        features.economics.compliance_risk_penalty_eur,
        &mut writer,
    );

    // ---- dimensions ---------------------------------------------------------
    let account_fit = account_fit_dimension(
        features.segment_match,
        employees,
        features.industry.as_deref(),
        features.ideal_employees_min,
        features.ideal_employees_max,
    );
    let persona_fit = persona_fit_dimension(&features.persona);
    let need_fit = need_fit_dimension(features.industry.as_deref(), &signals, features.now);
    let intent = intent_dimension(&signals, features.now);
    let timing = timing_dimension(account_fit, &signals, features.now);
    let email_stack_fit = email_stack_fit_dimension(&email_stack);
    let eu_fit = eu_residency_fit_dimension(features.eea_relevance);
    let reachability_score = reachability_dimension(&reachability);
    let evidence_score = evidence_quality_dimension(&evidence);
    let legal_score = legal_contactability_dimension(features.legal);
    let risk_score = risk_dimension(&risk, &features.outcomes);

    // ---- contributions and reason codes -------------------------------------
    let employment_detail = format_employees(
        employees,
        features
            .ideal_employees_min
            .min(features.ideal_employees_max),
        features
            .ideal_employees_min
            .max(features.ideal_employees_max),
    );
    let account_detail = format!("{}; {}", features.segment_match.label(), employment_detail);
    writer.contribution(
        "account fit",
        WEIGHT_ACCOUNT_FIT,
        account_fit,
        &account_detail,
    );

    let persona_detail = match (
        features.persona.job_title.as_deref(),
        features.persona.department.as_deref(),
    ) {
        (Some(title), Some(department)) if !title.trim().is_empty() => {
            format!("{title} ({department})")
        }
        (Some(title), _) if !title.trim().is_empty() => title.to_string(),
        _ => "no title/seniority on file".to_string(),
    };
    writer.contribution(
        "persona fit",
        WEIGHT_PERSONA_FIT,
        persona_fit,
        &persona_detail,
    );

    writer.contribution(
        "need fit",
        WEIGHT_NEED_FIT,
        need_fit,
        &format!(
            "{}; {} pain signal(s) (urgency {:.2})",
            if matches_icp_vertical(features.industry.as_deref()) {
                "ICP vertical"
            } else {
                "non-ICP or unknown vertical"
            },
            signals
                .iter()
                .filter(|s| PAIN_SIGNAL_TYPES.contains(&s.signal_type.as_str()))
                .count(),
            combined_urgency(
                &signals
                    .iter()
                    .filter(|s| PAIN_SIGNAL_TYPES.contains(&s.signal_type.as_str()))
                    .cloned()
                    .collect::<Vec<_>>(),
                features.now,
            )
        ),
    );

    let intent_detail = if signals.is_empty() {
        "no verified intent signal".to_string()
    } else {
        let strongest = signals
            .iter()
            .max_by(|a, b| {
                combined_urgency(std::slice::from_ref(a), features.now)
                    .partial_cmp(&combined_urgency(std::slice::from_ref(b), features.now))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|s| s.signal_type.clone())
            .unwrap_or_else(|| "unknown".into());
        format!("strongest {}", strongest)
    };
    writer.contribution("intent", WEIGHT_INTENT, intent, &intent_detail);

    let timing_urgency = combined_urgency(&signals, features.now);
    let timing_detail = if timing_urgency <= f32::EPSILON {
        format!(
            "no recent change signal (base fit {:.0})",
            clamp_unit100(account_fit)
        )
    } else {
        format!("change-signal urgency {timing_urgency:.2}")
    };
    writer.contribution("timing", WEIGHT_TIMING, timing, &timing_detail);

    let stack_detail = if email_stack.providers.is_empty() {
        "no email vendor hypothesis on file".to_string()
    } else {
        format!(
            "{} detected (confidence {:.2}, auth quality {:.2})",
            email_stack.providers.join(", "),
            email_stack.confidence,
            email_stack.authentication_quality
        )
    };
    writer.contribution(
        "email stack fit",
        WEIGHT_EMAIL_STACK_FIT,
        email_stack_fit,
        &stack_detail,
    );

    writer.contribution(
        "eu residency fit",
        WEIGHT_EU_RESIDENCY_FIT,
        eu_fit,
        match features.eea_relevance {
            EeaRelevance::InScope => "EEA in scope",
            EeaRelevance::OutOfScope => "outside EEA",
            EeaRelevance::Unknown => "EEA relevance unknown",
        },
    );

    writer.contribution(
        "reachability",
        WEIGHT_REACHABILITY,
        reachability_score,
        &format!(
            "{} verified contact point(s), best confidence {:.2}",
            reachability.verified_contact_points, reachability.best_confidence
        ),
    );

    writer.contribution(
        "evidence quality",
        WEIGHT_EVIDENCE_QUALITY,
        evidence_score,
        &format!(
            "{} observation(s), mean confidence {:.2}, newest {}",
            evidence.count,
            evidence.mean_confidence,
            match evidence.newest_age_days {
                Some(days) => format!("{days:.0}d old"),
                None => "unknown".to_string(),
            }
        ),
    );

    writer.contribution(
        "legal contactability",
        WEIGHT_LEGAL_CONTACTABILITY,
        legal_score,
        match features.legal {
            ContactDecision::Allowed => "allowed",
            ContactDecision::ApprovalRequired => "approval required",
            ContactDecision::Prohibited => "prohibited",
        },
    );

    writer.penalty(
        "risk",
        WEIGHT_RISK_PENALTY,
        risk_score,
        &format!(
            "{} complaint(s), {} negative reply(ies), {} bounce(s), frequency pressure {:.2}",
            risk.complaints,
            risk.negative_replies,
            features.outcomes.bounces,
            risk.frequency_pressure
        ),
    );

    // ---- clamp and record ---------------------------------------------------
    let raw_total = writer.points;
    let total = raw_total.clamp(TOTAL_MIN as i32, TOTAL_MAX as i32);
    if total != raw_total {
        writer.codes.push(format!(
            "{:+} total clamped to {total} (raw {raw_total})",
            total - raw_total
        ));
    }

    // ---- probabilities and the EV objective --------------------------------
    let p_qr = if features.legal == ContactDecision::Prohibited {
        0.0
    } else {
        p_qualified_reply(account_fit, persona_fit, need_fit, intent, email_stack_fit)
    };
    let p_meeting_given = if features.legal == ContactDecision::Prohibited {
        0.0
    } else {
        p_meeting_given_qualified_reply(timing, reachability_score, evidence_score)
    };
    let p_win_given = p_win_given_meeting(account_fit, legal_score, risk_score);
    let p_meeting = p_qr * p_meeting_given;
    let p_paid = p_meeting * p_win_given;

    // Penalties: explicit values win; otherwise derive from the dimensions.
    if reputation_penalty <= 0.0 {
        reputation_penalty = derived_reputation_penalty_eur(risk_score, ltv);
    }
    compliance_penalty =
        compliance_penalty.max(derived_compliance_penalty_eur(features.legal, ltv));

    let ev = expected_value_eur(
        p_qr,
        p_meeting_given,
        p_win_given,
        ltv,
        outreach_cost,
        reputation_penalty,
        compliance_penalty,
    );
    writer.codes.push(format!(
        "+0 expected value (separate decision objective): EUR {ev:.2}"
    ));

    OpportunityScore {
        account_fit: clamp_unit100(account_fit),
        persona_fit: clamp_unit100(persona_fit),
        need_fit: clamp_unit100(need_fit),
        intent: clamp_unit100(intent),
        timing: clamp_unit100(timing),
        email_stack_fit: clamp_unit100(email_stack_fit),
        eu_residency_fit: clamp_unit100(eu_fit),
        reachability: clamp_unit100(reachability_score),
        evidence_quality: clamp_unit100(evidence_score),
        legal_contactability: clamp_unit100(legal_score),
        risk: clamp_unit100(risk_score),
        p_qualified_reply: sanitize_probability(p_qr) as f32,
        p_meeting: sanitize_probability(p_meeting) as f32,
        p_paid: sanitize_probability(p_paid) as f32,
        expected_value_eur: ev,
        total: total as f32,
        reason_codes: writer.codes,
        scoring_version: SCORING_VERSION.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Insert every column of `sales_scores`
/// (migration 200_sales_autopilot_v2_unification.sql:403-427).
pub async fn persist(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    contact_id: Option<Uuid>,
    score: &OpportunityScore,
) -> Result<Uuid, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    if score.scoring_version.trim().is_empty() {
        return Err(SalesError::InvalidInput(
            "scoring_version must not be empty".into(),
        ));
    }
    let reason_codes = serde_json::to_value(&score.reason_codes)
        .map_err(|error| SalesError::InvalidInput(error.to_string()))?;

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_scores (
            id, tenant_id, account_id, contact_id,
            account_fit, persona_fit, need_fit, intent, timing, email_stack_fit,
            eu_residency_fit, reachability, evidence_quality, legal_contactability,
            risk, p_qualified_reply, p_meeting, p_paid, expected_value_eur,
            total, reason_codes, scoring_version, computed_at
         ) VALUES (
            $1, $2, $3, $4,
            $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17, $18, $19::float8::numeric,
            $20, $21, $22, NOW()
         )",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(account_id)
    .bind(contact_id)
    .bind(f64::from(score.account_fit))
    .bind(f64::from(score.persona_fit))
    .bind(f64::from(score.need_fit))
    .bind(f64::from(score.intent))
    .bind(f64::from(score.timing))
    .bind(f64::from(score.email_stack_fit))
    .bind(f64::from(score.eu_residency_fit))
    .bind(f64::from(score.reachability))
    .bind(f64::from(score.evidence_quality))
    .bind(f64::from(score.legal_contactability))
    .bind(f64::from(score.risk))
    .bind(f64::from(score.p_qualified_reply))
    .bind(f64::from(score.p_meeting))
    .bind(f64::from(score.p_paid))
    .bind(score.expected_value_eur)
    .bind(f64::from(score.total))
    .bind(reason_codes)
    .bind(&score.scoring_version)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(id)
}

/// Most recent stored score for an account, if any.
pub async fn latest_for_account(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<Option<OpportunityScore>, SalesError> {
    let row = sqlx::query(
        "SELECT account_fit, persona_fit, need_fit, intent, timing, email_stack_fit,
                eu_residency_fit, reachability, evidence_quality, legal_contactability,
                risk, p_qualified_reply, p_meeting, p_paid, expected_value_eur::float8 AS expected_value_eur,
                total, reason_codes, scoring_version
         FROM sales_scores
         WHERE tenant_id = $1 AND account_id = $2
         ORDER BY computed_at DESC, id DESC
         LIMIT 1",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let reason_codes_value: serde_json::Value = row
        .try_get("reason_codes")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let reason_codes: Vec<String> = serde_json::from_value(reason_codes_value)
        .map_err(|error| SalesError::Database(format!("malformed reason_codes JSON: {error}")))?;

    Ok(Some(OpportunityScore {
        account_fit: get_f64(&row, "account_fit")? as f32,
        persona_fit: get_f64(&row, "persona_fit")? as f32,
        need_fit: get_f64(&row, "need_fit")? as f32,
        intent: get_f64(&row, "intent")? as f32,
        timing: get_f64(&row, "timing")? as f32,
        email_stack_fit: get_f64(&row, "email_stack_fit")? as f32,
        eu_residency_fit: get_f64(&row, "eu_residency_fit")? as f32,
        reachability: get_f64(&row, "reachability")? as f32,
        evidence_quality: get_f64(&row, "evidence_quality")? as f32,
        legal_contactability: get_f64(&row, "legal_contactability")? as f32,
        risk: get_f64(&row, "risk")? as f32,
        p_qualified_reply: get_f64(&row, "p_qualified_reply")? as f32,
        p_meeting: get_f64(&row, "p_meeting")? as f32,
        p_paid: get_f64(&row, "p_paid")? as f32,
        expected_value_eur: get_f64(&row, "expected_value_eur")?,
        total: get_f64(&row, "total")? as f32,
        reason_codes,
        scoring_version: row
            .try_get("scoring_version")
            .map_err(|error| SalesError::Database(error.to_string()))?,
    }))
}

fn get_f64(row: &sqlx::postgres::PgRow, column: &str) -> Result<f64, SalesError> {
    row.try_get(column)
        .map_err(|error| SalesError::Database(format!("column {column}: {error}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::SignalType;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 11, 12, 0, 0).unwrap()
    }

    fn recent(days_ago: i64) -> SignalObservation {
        SignalObservation {
            signal_type: SignalType::TRIAL_SIGNUP.to_string(),
            strength: 0.9,
            observed_at: now() - chrono::Duration::days(days_ago),
        }
    }

    /// A realistic mid-funnel account used as the baseline for adversarial
    /// comparisons.
    fn base_features() -> ScoreFeatures {
        ScoreFeatures {
            now: now(),
            segment_match: SegmentMatch::Strong,
            employees: Some(220),
            industry: Some("B2B SaaS".into()),
            ideal_employees_min: 100,
            ideal_employees_max: 500,
            email_stack: EmailStackFeatures {
                providers: vec!["sendgrid".into()],
                confidence: 0.55,
                authentication_quality: 0.6,
            },
            eea_relevance: EeaRelevance::InScope,
            intent_signals: vec![recent(2)],
            persona: PersonaFeatures {
                job_title: Some("VP Engineering".into()),
                department: Some("Engineering".into()),
                seniority: Some("VP".into()),
            },
            reachability: ReachabilityFeatures {
                verified_contact_points: 2,
                best_confidence: 0.9,
            },
            evidence: EvidenceFeatures {
                count: 6,
                mean_confidence: 0.8,
                newest_age_days: Some(3.0),
            },
            legal: ContactDecision::Allowed,
            risk: RiskFeatures::default(),
            outcomes: OutcomeFeatures {
                delivered: 4,
                replies: 1,
                positive_replies: 1,
                ..OutcomeFeatures::default()
            },
            economics: EconomicsFeatures {
                expected_ltv_contribution_eur: 12_000.0,
                outreach_cost_eur: 8.0,
                ..EconomicsFeatures::default()
            },
        }
    }

    // ---- RELEASE GATE: opens never raise the score ------------------------

    #[test]
    fn opens_never_raise_the_score() {
        let mut no_opens = base_features();
        no_opens.outcomes.opens = 0;

        let mut many_opens = base_features();
        many_opens.outcomes.opens = 10_000;

        let a = score(&no_opens);
        let b = score(&many_opens);

        assert_eq!(a.total, b.total, "opens must not change the composite");
        assert_eq!(a.intent, b.intent, "opens must not raise intent");
        assert_eq!(a.timing, b.timing, "opens must not raise timing");
        assert_eq!(a.risk, b.risk, "opens must not change risk");
        assert_eq!(a.p_qualified_reply, b.p_qualified_reply);
        assert_eq!(a.p_meeting, b.p_meeting);
        assert_eq!(a.expected_value_eur, b.expected_value_eur);
        // The score table must not even carry an open-derived adjustment.
        assert!(!a.reason_codes.iter().any(|code| code.contains("open")));
    }

    // ---- reason-code reconciliation ---------------------------------------

    #[test]
    fn reason_codes_are_signed_and_reconcile_to_total() {
        let scenarios = [
            score(&base_features()),
            score(&ScoreFeatures {
                segment_match: SegmentMatch::Weak,
                employees: Some(500_000),
                industry: None,
                intent_signals: Vec::new(),
                legal: ContactDecision::Prohibited,
                risk: RiskFeatures {
                    complaints: 2,
                    negative_replies: 3,
                    frequency_pressure: 1.0,
                },
                outcomes: OutcomeFeatures {
                    bounces: 3,
                    complaints: 2,
                    unsubscribes: 3,
                    ..OutcomeFeatures::default()
                },
                ..ScoreFeatures::default()
            }),
        ];

        for opportunity in &scenarios {
            assert!(
                !opportunity.reason_codes.is_empty(),
                "reason codes must be non-empty"
            );
            for code in &opportunity.reason_codes {
                assert!(
                    reason_code_points(code).is_some(),
                    "every reason code must be signed with points: {code:?}"
                );
                assert!(
                    code.starts_with('+') || code.starts_with('-'),
                    "reason code must be signed: {code:?}"
                );
            }
            let sum = reconcile_reason_codes(&opportunity.reason_codes);
            assert!(
                (sum - opportunity.total).abs() <= REASON_CODE_RECONCILIATION_EPSILON,
                "codes sum {sum} != total {} in {:?}",
                opportunity.total,
                opportunity.reason_codes
            );
            assert!(opportunity.total >= TOTAL_MIN && opportunity.total <= TOTAL_MAX);
        }
    }

    #[test]
    fn clamped_total_records_a_signed_adjustment() {
        // Worst-case account + maximum risk drives the raw sum below zero, so
        // the composite must clamp to 0 and say why.
        let hostile = ScoreFeatures {
            now: now(),
            segment_match: SegmentMatch::Weak,
            employees: Some(900_000),
            industry: None,
            ideal_employees_min: 100,
            ideal_employees_max: 500,
            email_stack: EmailStackFeatures {
                providers: Vec::new(),
                confidence: 0.0,
                authentication_quality: 1.0,
            },
            eea_relevance: EeaRelevance::OutOfScope,
            intent_signals: Vec::new(),
            persona: PersonaFeatures::default(),
            reachability: ReachabilityFeatures::default(),
            evidence: EvidenceFeatures::default(),
            legal: ContactDecision::Prohibited,
            risk: RiskFeatures {
                complaints: 9,
                negative_replies: 9,
                frequency_pressure: 1.0,
            },
            outcomes: OutcomeFeatures {
                complaints: 9,
                bounces: 9,
                unsubscribes: 9,
                ..OutcomeFeatures::default()
            },
            economics: EconomicsFeatures::default(),
        };
        let opportunity = score(&hostile);
        assert_eq!(opportunity.total, 0.0);
        assert!(
            opportunity
                .reason_codes
                .iter()
                .any(|code| code.contains("total clamped to 0")),
            "expected a clamp adjustment code: {:?}",
            opportunity.reason_codes
        );
        let sum = reconcile_reason_codes(&opportunity.reason_codes);
        assert!((sum - opportunity.total).abs() <= REASON_CODE_RECONCILIATION_EPSILON);
    }

    // ---- dimension range validation / hostile numbers ---------------------

    #[test]
    fn every_dimension_is_bounded_even_with_hostile_inputs() {
        let mut hostile = base_features();
        hostile.employees = Some(i64::MAX);
        hostile.email_stack.confidence = f32::NAN;
        hostile.email_stack.authentication_quality = f32::NEG_INFINITY;
        hostile.reachability.best_confidence = f32::INFINITY;
        hostile.evidence.mean_confidence = f32::NAN;
        hostile.evidence.newest_age_days = Some(f32::INFINITY);
        hostile.risk.frequency_pressure = f32::NAN;
        hostile.intent_signals = vec![SignalObservation {
            signal_type: SignalType::FUNDING.to_string(),
            strength: f32::NAN,
            observed_at: now(),
        }];
        hostile.economics.expected_ltv_contribution_eur = f64::INFINITY;
        hostile.economics.outreach_cost_eur = f64::NAN;

        let opportunity = score(&hostile);
        assert!(opportunity.total.is_finite());
        assert!(opportunity.expected_value_eur.is_finite());
        for (label, value) in [
            ("account_fit", opportunity.account_fit),
            ("persona_fit", opportunity.persona_fit),
            ("need_fit", opportunity.need_fit),
            ("intent", opportunity.intent),
            ("timing", opportunity.timing),
            ("email_stack_fit", opportunity.email_stack_fit),
            ("eu_residency_fit", opportunity.eu_residency_fit),
            ("reachability", opportunity.reachability),
            ("evidence_quality", opportunity.evidence_quality),
            ("legal_contactability", opportunity.legal_contactability),
            ("risk", opportunity.risk),
        ] {
            assert!(value.is_finite(), "{label} must be finite");
            assert!(
                (0.0..=100.0).contains(&value),
                "{label} {value} out of 0..=100"
            );
        }
        assert!((0.0..=1.0).contains(&opportunity.p_qualified_reply));
        assert!((0.0..=1.0).contains(&opportunity.p_meeting));
        assert!((0.0..=1.0).contains(&opportunity.p_paid));
        // Sanitation is never silent.
        assert!(opportunity
            .reason_codes
            .iter()
            .any(|code| code.contains("out of range") || code.contains("above range")));
    }

    #[test]
    fn dimension_helpers_survive_nan_and_infinity() {
        let hostile_signals = vec![SignalObservation {
            signal_type: SignalType::FUNDING.to_string(),
            strength: f32::NAN,
            observed_at: now(),
        }];
        for value in [
            account_fit_dimension(SegmentMatch::Strong, Some(i64::MAX), None, 0, 10),
            account_fit_dimension(SegmentMatch::Unknown, None, None, 100, 10),
            persona_fit_dimension(&PersonaFeatures::default()),
            need_fit_dimension(None, &hostile_signals, now()),
            intent_dimension(&hostile_signals, now()),
            timing_dimension(f32::NAN, &hostile_signals, now()),
            email_stack_fit_dimension(&EmailStackFeatures {
                providers: vec!["x".into()],
                confidence: f32::NAN,
                authentication_quality: f32::INFINITY,
            }),
            eu_residency_fit_dimension(EeaRelevance::Unknown),
            reachability_dimension(&ReachabilityFeatures {
                verified_contact_points: u32::MAX,
                best_confidence: f32::NEG_INFINITY,
            }),
            evidence_quality_dimension(&EvidenceFeatures {
                count: u32::MAX,
                mean_confidence: f32::INFINITY,
                newest_age_days: Some(f32::NAN),
            }),
            legal_contactability_dimension(ContactDecision::Prohibited),
            risk_dimension(
                &RiskFeatures {
                    complaints: u32::MAX,
                    negative_replies: u32::MAX,
                    frequency_pressure: f32::NAN,
                },
                &OutcomeFeatures {
                    complaints: u32::MAX,
                    unsubscribes: u32::MAX,
                    bounces: u32::MAX,
                    ..OutcomeFeatures::default()
                },
            ),
        ] {
            assert!(value.is_finite(), "dimension returned {value}");
        }
    }

    #[test]
    fn strict_validator_rejects_hostile_features() {
        let mut features = base_features();
        features.email_stack.confidence = f32::NAN;
        assert!(matches!(
            validate_features(&features),
            Err(SalesError::InvalidInput(_))
        ));

        let mut features = base_features();
        features.employees = Some(-5);
        assert!(matches!(
            validate_features(&features),
            Err(SalesError::InvalidInput(_))
        ));

        let mut features = base_features();
        features.intent_signals = vec![SignalObservation {
            signal_type: "funding".into(),
            strength: 1.5,
            observed_at: now(),
        }];
        assert!(matches!(
            validate_features(&features),
            Err(SalesError::InvalidInput(_))
        ));

        let mut features = base_features();
        features.economics.outreach_cost_eur = -1.0;
        assert!(matches!(
            validate_features(&features),
            Err(SalesError::InvalidInput(_))
        ));

        assert!(validate_features(&base_features()).is_ok());
    }

    // ---- EV objective ranking ---------------------------------------------

    #[test]
    fn ev_prefers_real_ltv_over_a_high_meeting_probability() {
        // Prospect A: extremely likely to meet, but the won deal is worth €0.
        let ev_a = expected_value_eur(0.9, 0.9, 0.9, 0.0, 10.0, 0.0, 0.0);
        // Prospect B: modest meeting probability, real LTV contribution.
        let ev_b = expected_value_eur(0.2, 0.5, 0.3, 20_000.0, 10.0, 0.0, 0.0);
        assert!(ev_b > ev_a, "EV ranking must follow LTV: {ev_b} vs {ev_a}");
        assert!(ev_a < 0.0, "a €0-LTV prospect is pure cost");
    }

    #[test]
    fn ev_ranking_is_stable_across_a_portfolio() {
        let candidates = [
            (
                "high_meeting_no_ltv",
                (0.95, 0.95, 0.95, 0.0, 5.0, 0.0, 0.0),
            ),
            ("modest_with_ltv", (0.3, 0.4, 0.4, 15_000.0, 20.0, 0.0, 0.0)),
            ("strong_with_ltv", (0.5, 0.6, 0.5, 40_000.0, 20.0, 0.0, 0.0)),
            (
                "strong_but_penalised",
                (0.5, 0.6, 0.5, 40_000.0, 20.0, 30_000.0, 0.0),
            ),
        ];
        let scored: Vec<(&str, f64)> = candidates
            .iter()
            .map(|(name, args)| {
                (
                    *name,
                    expected_value_eur(args.0, args.1, args.2, args.3, args.4, args.5, args.6),
                )
            })
            .collect();
        let by_name = |name: &str| {
            scored
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .map(|(_, value)| *value)
                .expect("candidate present")
        };
        assert!(by_name("strong_with_ltv") > by_name("modest_with_ltv"));
        assert!(by_name("modest_with_ltv") > by_name("high_meeting_no_ltv"));
        assert!(by_name("strong_but_penalised") < 0.0);
        assert!(by_name("strong_with_ltv") > 0.0);
    }

    #[test]
    fn outreach_cost_can_make_a_marginal_prospect_negative() {
        // 0.25 × 0.4 × 0.5 = 0.05 expected win rate on a €100 LTV → €5 gross.
        let without_cost = expected_value_eur(0.25, 0.4, 0.5, 100.0, 0.0, 0.0, 0.0);
        let with_cost = expected_value_eur(0.25, 0.4, 0.5, 100.0, 6.0, 0.0, 0.0);
        assert!(without_cost > 0.0);
        assert!(
            with_cost < 0.0,
            "cost must be able to kill a marginal prospect"
        );
        assert!((without_cost - 5.0).abs() < 1e-9);
    }

    #[test]
    fn reputation_and_compliance_penalties_can_flip_positive_ev() {
        let base = expected_value_eur(0.5, 0.5, 0.5, 1_000.0, 0.0, 0.0, 0.0);
        assert!((base - 125.0).abs() < 1e-9);
        let reputation_hit = expected_value_eur(0.5, 0.5, 0.5, 1_000.0, 0.0, 200.0, 0.0);
        assert!(reputation_hit < 0.0);
        let compliance_hit = expected_value_eur(0.5, 0.5, 0.5, 1_000.0, 0.0, 0.0, 200.0);
        assert!(compliance_hit < 0.0);
    }

    #[test]
    fn ev_is_total_for_hostile_numbers() {
        for value in [
            expected_value_eur(f64::NAN, 0.5, 0.5, 1_000.0, 0.0, 0.0, 0.0),
            expected_value_eur(2.0, -1.0, f64::INFINITY, 1_000.0, 0.0, 0.0, 0.0),
            expected_value_eur(0.5, 0.5, 0.5, f64::INFINITY, f64::NAN, -10.0, -10.0),
            expected_value_eur(0.5, 0.5, 0.5, -5.0, -5.0, -5.0, -5.0),
        ] {
            assert!(value.is_finite(), "EV returned {value}");
        }
        assert_eq!(
            expected_value_eur(f64::NAN, 0.5, 0.5, 1_000.0, 0.0, 0.0, 0.0),
            0.0
        );
    }

    #[test]
    fn prohibited_legal_verdict_removes_expected_value() {
        let mut features = base_features();
        features.legal = ContactDecision::Prohibited;
        let opportunity = score(&features);
        assert_eq!(opportunity.p_qualified_reply, 0.0);
        assert_eq!(opportunity.p_meeting, 0.0);
        assert_eq!(opportunity.p_paid, 0.0);
        assert!(
            opportunity.expected_value_eur < 0.0,
            "a prohibited contact must never look profitable: {}",
            opportunity.expected_value_eur
        );
    }

    #[test]
    fn derived_penalties_are_documented_and_bounded() {
        assert_eq!(derived_reputation_penalty_eur(0.0, 10_000.0), 0.0);
        let low_risk = derived_reputation_penalty_eur(50.0, 10_000.0);
        let high_risk = derived_reputation_penalty_eur(100.0, 10_000.0);
        assert!(
            high_risk > low_risk && low_risk > 0.0,
            "{high_risk} vs {low_risk}"
        );
        assert_eq!(high_risk, 20.0, "0.002 × 10 000 × 1.0");
        assert_eq!(derived_reputation_penalty_eur(f32::NAN, 10_000.0), 0.0);
        assert_eq!(
            derived_compliance_penalty_eur(ContactDecision::Allowed, 10_000.0),
            0.0
        );
        assert!(derived_compliance_penalty_eur(ContactDecision::Prohibited, 10_000.0) > 0.0);
        assert_eq!(
            derived_compliance_penalty_eur(ContactDecision::Prohibited, f64::NAN),
            0.0
        );
    }

    // ---- timing / signal decay --------------------------------------------

    #[test]
    fn strong_signal_raises_timing_and_stale_signal_does_not() {
        let base_fit = 80.0;
        let no_signal = timing_dimension(base_fit, &[], now());
        let strong_recent = timing_dimension(base_fit, &[recent(0)], now());
        let stale = timing_dimension(base_fit, &[recent(365)], now());

        assert!(
            strong_recent > no_signal + 10.0,
            "fresh signal must raise timing: {strong_recent} vs {no_signal}"
        );
        assert!(
            (stale - no_signal).abs() < 0.5,
            "a year-old signal must not raise timing: {stale} vs {no_signal}"
        );
        assert!(stale >= no_signal, "decay must not invert the contribution");

        // Monotone: older signal → lower (or equal) timing.
        let mut previous = strong_recent;
        for days in [1, 2, 4, 8, 16, 32, 64, 128] {
            let current = timing_dimension(base_fit, &[recent(days)], now());
            assert!(
                current <= previous + 1e-4,
                "timing rose from {previous} to {current} at {days}d"
            );
            previous = current;
        }
    }

    #[test]
    fn intent_dimension_decays_and_caps_breadth() {
        assert_eq!(intent_dimension(&[], now()), 0.0);
        let fresh = intent_dimension(&[recent(0)], now());
        let stale = intent_dimension(&[recent(1000)], now());
        assert!(fresh > 0.0);
        assert!(stale <= f32::EPSILON);

        let many: Vec<SignalObservation> = (0..10_000)
            .map(|_| SignalObservation {
                signal_type: SignalType::TRIAL_SIGNUP.to_string(),
                strength: 1.0,
                observed_at: now(),
            })
            .collect();
        let crowded = intent_dimension(&many, now());
        assert!(crowded.is_finite());
        assert!(
            crowded <= 110.0 + f32::EPSILON,
            "breadth bonus must be capped: {crowded}"
        );
        // The composite bounds it with a recorded reason.
        let mut features = base_features();
        features.intent_signals = many;
        let opportunity = score(&features);
        assert!(opportunity.intent <= 100.0);
        assert!(opportunity
            .reason_codes
            .iter()
            .any(|code| code.contains("intent dimension")));
    }

    // ---- probabilities -----------------------------------------------------

    #[test]
    fn probabilities_stay_in_unit_interval() {
        let opportunity = score(&base_features());
        for (label, value) in [
            ("p_qualified_reply", opportunity.p_qualified_reply),
            ("p_meeting", opportunity.p_meeting),
            ("p_paid", opportunity.p_paid),
        ] {
            assert!(value.is_finite(), "{label} non-finite");
            assert!((0.0..=1.0).contains(&value), "{label} = {value}");
        }
        // The cumulative ladder is non-increasing.
        assert!(opportunity.p_meeting <= opportunity.p_qualified_reply + 1e-6);
        assert!(opportunity.p_paid <= opportunity.p_meeting + 1e-6);

        for value in [
            p_qualified_reply(f32::NAN, f32::INFINITY, -1.0, 1e9, 0.0),
            p_meeting_given_qualified_reply(f32::NAN, f32::NEG_INFINITY, 1e9),
            p_win_given_meeting(f32::INFINITY, f32::NAN, -5.0),
        ] {
            assert!(value.is_finite() && (0.0..=1.0).contains(&value));
        }
    }

    #[test]
    fn expected_value_eur_comes_from_the_objective_not_a_constant() {
        let mut features = base_features();
        let low_ltv = score(&features);
        features.economics.expected_ltv_contribution_eur = 120_000.0;
        let high_ltv = score(&features);
        // Same dimensions, 10× LTV: the EV must move with the objective.
        assert!(high_ltv.expected_value_eur > low_ltv.expected_value_eur);
        assert_eq!(low_ltv.total, high_ltv.total, "composite ignores LTV");
        // Recover the implied win probability from the low-LTV EV (the only
        // non-LTV term is the €8 outreach cost) and check the 10× prediction.
        let implied_p = (low_ltv.expected_value_eur + 8.0) / 12_000.0;
        let expected_high = implied_p * 120_000.0 - 8.0;
        assert!(
            (high_ltv.expected_value_eur - expected_high).abs() < 1e-6,
            "EV must be linear in LTV: {} vs {expected_high}",
            high_ltv.expected_value_eur
        );
    }

    #[test]
    fn scoring_is_deterministic() {
        let features = base_features();
        let first = score(&features);
        let second = score(&features);
        assert_eq!(first.total, second.total);
        assert_eq!(first.reason_codes, second.reason_codes);
        assert_eq!(first.expected_value_eur, second.expected_value_eur);
        assert_eq!(first.scoring_version, SCORING_VERSION);
    }

    #[test]
    fn scoring_version_is_named_and_non_empty() {
        assert!(!SCORING_VERSION.trim().is_empty());
        assert!(SCORING_VERSION.starts_with("sales-score-v"));
    }

    #[test]
    fn weights_sum_to_one_and_bounds_are_sane() {
        let positive = WEIGHT_ACCOUNT_FIT
            + WEIGHT_PERSONA_FIT
            + WEIGHT_NEED_FIT
            + WEIGHT_INTENT
            + WEIGHT_TIMING
            + WEIGHT_EMAIL_STACK_FIT
            + WEIGHT_EU_RESIDENCY_FIT
            + WEIGHT_REACHABILITY
            + WEIGHT_EVIDENCE_QUALITY
            + WEIGHT_LEGAL_CONTACTABILITY;
        assert!(
            (positive - 1.0).abs() < 1e-6,
            "positive weights sum {positive}"
        );
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(WEIGHT_RISK_PENALTY > 0.0 && WEIGHT_RISK_PENALTY < 1.0);
            assert_eq!(TOTAL_MIN, 0.0);
            assert_eq!(TOTAL_MAX, 100.0);
        }
    }

    #[test]
    fn reason_code_points_parser_is_strict() {
        assert_eq!(reason_code_points("+18 account fit: SaaS"), Some(18));
        assert_eq!(reason_code_points("-4 risk: none"), Some(-4));
        assert_eq!(reason_code_points("+0 expected value: EUR 1.00"), Some(0));
        assert_eq!(reason_code_points("18 missing sign"), None);
        assert_eq!(reason_code_points("+ no digits"), None);
        assert_eq!(reason_code_points(""), None);
    }
}
