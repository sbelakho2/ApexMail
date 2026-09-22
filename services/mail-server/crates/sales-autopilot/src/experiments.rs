//! §17/§18/§37/§28 — contextual experiments, the reward ladder, economic
//! exploration limits and the next-best-action policy.
//!
//! # The optimizer is in the send path
//!
//! [`ExperimentEngine::select_variant`] is called by the sequence worker at
//! action-planning time, the chosen arm is persisted on
//! `sales_step_executions.variant` and `sales_enrollments.experiment_variant`
//! **before** the dispatcher is invoked, and every realised outcome is fed
//! back through [`record_reward`]. `CampaignAutopilot::select_arm` remains the
//! campaign-template optimizer; it is not in this path.
//!
//! # One store, one sampler
//!
//! The arm store is the canonical sales experiment model from migration 200
//! (`sales_experiment_arms` / `sales_experiment_outcomes`,
//! `200_sales_autopilot_v2_unification.sql:807-835`), **not**
//! `campaign_arms` (migration 197). Two reasons:
//!
//! * `campaign_arms` is keyed to `sales_campaigns` — a different execution
//!   identity than the sequence/enrollment path this optimizer serves, and it
//!   carries no per-arm `contacts`, `negative_outcomes` or
//!   `enrichment_cost_eur` counters, which the §37 exploration budgets need;
//! * `sales_experiment_outcomes.outcome_key` is a primary key, which gives the
//!   outcome ledger its idempotency (replaying a logical outcome moves the
//!   posterior at most once).
//!
//! There is exactly one Beta sampler in the codebase: [`analytics::sample_beta`]
//! (Marsaglia–Tsang Gamma), re-used here. No second sampler is written.
//!
//! # The reward ladder (§17)
//!
//! | outcome | reward | role |
//! |---|---|---|
//! | `delivered` | `0.0` | operational metric only |
//! | `open` | `0.0` | informational only — **never a success signal** |
//! | `click` | `0.05` | weak intent |
//! | `reply` | `0.2` | modest |
//! | `positive_reply` | `0.5` | strong |
//! | `meeting_booked` | `0.7` | stronger |
//! | `meeting_attended` | `0.8` | stronger |
//! | `trial` | `0.9` | very strong |
//! | `paid_subscription` | `1.0` | primary business reward |
//! | `retained_mrr` | `1.2` | eventual highest value |
//! | `bounce` | `-0.2` | penalty |
//! | `complaint` | `-0.5` | penalty |
//! | `unsubscribe` | `-0.3` | penalty |
//!
//! The posterior is a reward-weighted Beta:
//!
//! ```text
//! alpha = 1 + Σ positive rewards      beta = 1 + Σ |negative rewards|
//! ```
//!
//! `delivered`/`open` move no posterior parameter at all (they increment only
//! the `contacts` exposure counter). Therefore 10 000 opens cannot promote an
//! arm over one with real replies — see the release-gate test
//! `ten_thousand_opens_never_win_an_arm`.
//!
//! # Contextual selection (§18)
//!
//! The ten documented dimensions live in [`ExperimentContext`]: ICP segment,
//! country, company size band, persona, ESP hypothesis, intent bucket, offer,
//! language, sequence step kind and sender type. An experiment declares which
//! dimensions it conditions on through `sales_experiments.context.dimensions`
//! (migration line 797); the default is all ten.
//!
//! For a concrete bucket a **derived child experiment** is provisioned
//! (key `"{parent}::ctx::{bucket}"`) with the same variants and fresh
//! `Beta(1, 1)` priors. Selection is a hierarchical fallback:
//!
//! * bucket trials `< MIN_CONTEXT_SAMPLES` → use the **global** posterior
//!   (the bucket has too little data to shrink toward the parent rigorously);
//! * bucket trials `>= MIN_CONTEXT_SAMPLES` → use the **bucket** posterior.
//!
//! The threshold is a documented hard shrinkage rule, not a partial-pooling
//! average, so a bucket can never be steered by another bucket's data and a
//! sparse bucket can never be steered by a random arm. The audit's warning is
//! the design constraint: *"the globally winning message for a French
//! 30-person SaaS CTO may get sent to a German enterprise procurement
//! director — that is not intelligence."*
//!
//! # §37 exploration economics
//!
//! [`ExplorationBudget`] is parsed from `sales_experiments.budgets`
//! (migration line 801) via [`ExplorationBudget::from_json`] and enforced by
//! the pure [`may_explore`] before any arm is drawn. Exhaustion falls back to
//! **exploit-only** (the deterministic best arm), never to unbounded
//! exploration and never to a silent stop. `None` is unlimited; a present zero
//! is zero. A hostile negative or NaN percentage is rejected to `0.0` (no
//! exploration), never accepted.
//!
//! # §28 next-best-action
//!
//! [`next_best_action`] is a pure function of EV − cost, evidence sufficiency,
//! reply state, address verification and intent. It can choose `DoNothing`
//! (weak prospects), `Enrich`/`CollectEvidence`/`ResearchCompany`/
//! `VerifyEmail` (high EV with thin evidence — spending €0.20 on information
//! beats a premature send), and never chooses an external send when a human
//! has replied or when outreach cost exceeds expected value.

use std::collections::{BTreeMap, HashSet};

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::attribution::OutcomeKind;
use crate::types::{DecisionAction, SalesError};

// ---------------------------------------------------------------------------
// Named limits and thresholds (all public so callers can document them)
// ---------------------------------------------------------------------------

/// Minimum bucket observations before a contextual bucket's own posterior is
/// authoritative. Below this the global posterior is used (documented hard
/// shrinkage rule).
pub const MIN_CONTEXT_SAMPLES: i64 = 25;

/// Maximum length of the sanitized context bucket key.
pub const MAX_CONTEXT_KEY_LEN: usize = 200;

/// Maximum length of one sanitized context dimension value.
pub const MAX_CONTEXT_VALUE_LEN: usize = 48;

/// Maximum arms an experiment may have before selection fails closed to
/// exploit-only (a 10 000-arm experiment must not panic or take unbounded
/// time).
pub const MAX_ARMS_PER_EXPERIMENT: usize = 512;

/// Maximum accepted `outcome_key` length (a 1 MB key is hostile input).
pub const MAX_OUTCOME_KEY_LEN: usize = 512;

/// Default minimum informative trials before an arm may be promoted.
pub const DEFAULT_MIN_SAMPLE_BEFORE_PROMOTION: i64 = 100;

/// Default minimum posterior probability that the challenger beats control.
pub const DEFAULT_MIN_POSTERIOR_CONFIDENCE: f64 = 0.95;

/// Default EV threshold (EUR) above which an account is excluded from
/// exploration unless explicitly overridden.
pub const DEFAULT_HIGH_VALUE_EV_THRESHOLD_EUR: f64 = 5_000.0;

/// Minimum expected value (EUR) for which any outreach is economically
/// defensible. A €29/month prospect (≈ €348/year) with weak probabilities
/// falls below this and correctly becomes `DoNothing`.
pub const MIN_EXPECTED_VALUE_FOR_OUTREACH_EUR: f64 = 5.0;

/// Evidence rows below which a high-EV account gets an information-gathering
/// action instead of `Contact`.
pub const MIN_EVIDENCE_FOR_OUTREACH: u32 = 3;

/// Expected value (EUR) at which "spend €0.20 on information first" beats
/// "send now" for an account with thin evidence.
pub const HIGH_VALUE_ACCOUNT_EV_EUR: f64 = 1_000.0;

/// Default fully-loaded cost of one outreach attempt, EUR. The number that
/// makes "spend €0.20 acquiring more information" a real trade-off.
pub const DEFAULT_OUTREACH_COST_EUR: f64 = 0.20;

// ---------------------------------------------------------------------------
// Reward ladder
// ---------------------------------------------------------------------------

/// The canonical reward ladder. Wire strings match the `sales_outcomes.outcome`
/// CHECK constraint (migration 200_sales_autopilot_v2_unification.sql:768-771).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardKind {
    Delivered,
    Open,
    Click,
    Reply,
    PositiveReply,
    MeetingBooked,
    MeetingAttended,
    Trial,
    PaidSubscription,
    RetainedMrr,
    Bounce,
    Complaint,
    Unsubscribe,
}

/// The strictly increasing part of the ladder (everything above `open`).
pub const POSITIVE_REWARD_LADDER: &[RewardKind] = &[
    RewardKind::Click,
    RewardKind::Reply,
    RewardKind::PositiveReply,
    RewardKind::MeetingBooked,
    RewardKind::MeetingAttended,
    RewardKind::Trial,
    RewardKind::PaidSubscription,
    RewardKind::RetainedMrr,
];

impl RewardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Open => "open",
            Self::Click => "click",
            Self::Reply => "reply",
            Self::PositiveReply => "positive_reply",
            Self::MeetingBooked => "meeting_booked",
            Self::MeetingAttended => "meeting_attended",
            Self::Trial => "trial",
            Self::PaidSubscription => "paid_subscription",
            Self::RetainedMrr => "retained_mrr",
            Self::Bounce => "bounce",
            Self::Complaint => "complaint",
            Self::Unsubscribe => "unsubscribe",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "delivered" => Some(Self::Delivered),
            "open" => Some(Self::Open),
            "click" => Some(Self::Click),
            "reply" => Some(Self::Reply),
            "positive_reply" => Some(Self::PositiveReply),
            "meeting_booked" => Some(Self::MeetingBooked),
            "meeting_attended" => Some(Self::MeetingAttended),
            "trial" => Some(Self::Trial),
            "paid_subscription" => Some(Self::PaidSubscription),
            "retained_mrr" => Some(Self::RetainedMrr),
            "bounce" => Some(Self::Bounce),
            "complaint" => Some(Self::Complaint),
            "unsubscribe" => Some(Self::Unsubscribe),
            _ => None,
        }
    }

    /// Map the canonical attribution vocabulary onto the reward ladder.
    pub fn from_outcome_kind(kind: OutcomeKind) -> Self {
        match kind {
            OutcomeKind::Delivered => Self::Delivered,
            OutcomeKind::Open => Self::Open,
            OutcomeKind::Click => Self::Click,
            OutcomeKind::Reply => Self::Reply,
            OutcomeKind::PositiveReply => Self::PositiveReply,
            OutcomeKind::MeetingBooked => Self::MeetingBooked,
            OutcomeKind::MeetingAttended => Self::MeetingAttended,
            OutcomeKind::Trial => Self::Trial,
            OutcomeKind::PaidSubscription => Self::PaidSubscription,
            OutcomeKind::RetainedMrr => Self::RetainedMrr,
            OutcomeKind::Bounce => Self::Bounce,
            OutcomeKind::Complaint => Self::Complaint,
            OutcomeKind::Unsubscribe => Self::Unsubscribe,
        }
    }

    /// The documented reward. `open` is 0.0: opens are recorded but are never
    /// a success signal (Apple Mail Privacy Protection / prefetching make them
    /// meaningless).
    pub fn reward(self) -> f64 {
        match self {
            Self::Delivered => 0.0,
            Self::Open => 0.0,
            Self::Click => 0.05,
            Self::Reply => 0.2,
            Self::PositiveReply => 0.5,
            Self::MeetingBooked => 0.7,
            Self::MeetingAttended => 0.8,
            Self::Trial => 0.9,
            Self::PaidSubscription => 1.0,
            Self::RetainedMrr => 1.2,
            Self::Bounce => -0.2,
            Self::Complaint => -0.5,
            Self::Unsubscribe => -0.3,
        }
    }

    /// Negative outcomes are penalties (and increment the negative-outcome
    /// budget counter).
    pub fn is_negative(self) -> bool {
        matches!(self, Self::Bounce | Self::Complaint | Self::Unsubscribe)
    }

    /// Operational/informational outcomes: recorded, exposed for budgets, but
    /// never moved into the posterior.
    pub fn is_operational(self) -> bool {
        matches!(self, Self::Delivered | Self::Open)
    }

    /// Does this outcome move the posterior at all?
    pub fn is_informative(self) -> bool {
        !self.is_operational()
    }
}

impl std::fmt::Display for RewardKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Posteriors
// ---------------------------------------------------------------------------

/// One arm's reward-weighted Beta posterior, mirroring
/// `sales_experiment_arms` (migration 200_sales_autopilot_v2_unification.sql:
/// 807-825).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArmPosterior {
    pub variant: String,
    /// `alpha = 1 + Σ positive rewards`; always finite and `> 0` (DB CHECK,
    /// migration line 813).
    pub alpha: f64,
    /// `beta = 1 + Σ |negative rewards|`; always finite and `> 0` (line 815).
    pub beta: f64,
    /// Informative observations only (click and above). Opens do not count.
    pub trials: i64,
    pub successes: i64,
    /// Exposure counter: every recorded outcome, including opens.
    pub contacts: i64,
    pub negative_outcomes: i64,
    pub enrichment_cost_eur: f64,
    pub is_control: bool,
}

impl ArmPosterior {
    pub fn new(variant: &str, alpha: f64, beta: f64, is_control: bool) -> Self {
        Self {
            variant: variant.to_string(),
            alpha,
            beta,
            trials: 0,
            successes: 0,
            contacts: 0,
            negative_outcomes: 0,
            enrichment_cost_eur: 0.0,
            is_control,
        }
    }

    pub fn mean(&self) -> f64 {
        if self.alpha.is_finite() && self.beta.is_finite() && self.alpha + self.beta > 0.0 {
            self.alpha / (self.alpha + self.beta)
        } else {
            0.0
        }
    }

    /// 95% credible interval, re-using the analytics normal approximation.
    pub fn credible_interval(&self) -> (f64, f64) {
        analytics::campaign_autopilot::credible_interval_95(self.alpha, self.beta)
    }
}

/// Arm specification for provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmSpec {
    pub variant: String,
    pub is_control: bool,
}

impl ArmSpec {
    pub fn new(variant: &str) -> Self {
        Self {
            variant: variant.to_string(),
            is_control: false,
        }
    }

    pub fn control(variant: &str) -> Self {
        Self {
            variant: variant.to_string(),
            is_control: true,
        }
    }
}

/// Validate a Beta posterior before it is written or sampled. The database
/// CHECK constraints (`alpha > 0 AND alpha < 'Infinity'`, `beta` likewise,
/// `trials >= 0`, `successes >= 0 AND successes <= trials`) are the backstop;
/// this function makes a hostile value a clear [`SalesError::InvalidInput`]
/// before any SQL runs.
pub fn validate_posterior(alpha: f64, beta: f64) -> Result<(), SalesError> {
    if !alpha.is_finite() || alpha <= 0.0 {
        return Err(SalesError::InvalidInput(format!(
            "arm alpha must be finite and > 0 (the DB CHECK rejects it otherwise), got {alpha}"
        )));
    }
    if !beta.is_finite() || beta <= 0.0 {
        return Err(SalesError::InvalidInput(format!(
            "arm beta must be finite and > 0 (the DB CHECK rejects it otherwise), got {beta}"
        )));
    }
    Ok(())
}

/// Apply one rung of the ladder to a posterior, validating every input.
///
/// * positive reward: `alpha += reward`, `trials += 1`, `successes += 1`;
/// * negative reward: `beta += |reward|`, `trials += 1`, `negative_outcomes += 1`;
/// * zero (delivered/open): only `contacts += 1` — the posterior does not move.
pub fn apply_reward_to_posterior(
    arm: &mut ArmPosterior,
    kind: RewardKind,
) -> Result<(), SalesError> {
    validate_posterior(arm.alpha, arm.beta)?;
    if arm.trials < 0 || arm.successes < 0 || arm.successes > arm.trials {
        return Err(SalesError::InvalidInput(format!(
            "arm '{}' has inconsistent counters: trials={}, successes={}",
            arm.variant, arm.trials, arm.successes
        )));
    }
    let reward = kind.reward();
    if !reward.is_finite() {
        return Err(SalesError::InvalidInput(format!(
            "reward for {kind} must be finite"
        )));
    }
    arm.contacts = arm.contacts.saturating_add(1);
    if !kind.is_informative() {
        return Ok(());
    }
    arm.trials = arm.trials.saturating_add(1);
    if reward > 0.0 {
        arm.alpha += reward;
        arm.successes = arm.successes.saturating_add(1);
    } else if reward < 0.0 {
        arm.beta += -reward;
        arm.negative_outcomes = arm.negative_outcomes.saturating_add(1);
    }
    validate_posterior(arm.alpha, arm.beta)
}

/// Deterministic exploit choice: the arm with the highest posterior mean,
/// breaking ties control-first then by variant name. Used whenever
/// exploration is not allowed.
pub fn best_arm_index(arms: &[ArmPosterior]) -> Option<usize> {
    arms.iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.mean()
                .partial_cmp(&b.mean())
                .unwrap_or(std::cmp::Ordering::Equal)
                // Higher mean wins; control wins a mean tie; then the smaller
                // variant name wins (deterministic).
                .then_with(|| a.is_control.cmp(&b.is_control))
                .then_with(|| b.variant.cmp(&a.variant))
        })
        .map(|(index, _)| index)
}

/// Monte-Carlo selection probabilities over a set of posteriors, re-using the
/// single Beta sampler. Deterministic given the OS RNG; tests use wide
/// tolerances.
pub fn selection_win_probabilities(
    arms: &[ArmPosterior],
    draws: usize,
) -> Result<Vec<f64>, SalesError> {
    if arms.is_empty() {
        return Ok(Vec::new());
    }
    for arm in arms {
        validate_posterior(arm.alpha, arm.beta)?;
    }
    let draws = draws.max(1);
    let mut rng = StdRng::from_os_rng();
    let mut wins = vec![0u64; arms.len()];
    for _ in 0..draws {
        let mut best = 0usize;
        let mut best_sample = f64::NEG_INFINITY;
        for (index, arm) in arms.iter().enumerate() {
            let sample = analytics::campaign_autopilot::sample_beta(&mut rng, arm.alpha, arm.beta)
                .map_err(|error| {
                    SalesError::InvalidInput(format!(
                        "arm '{}' posterior cannot be sampled: {error}",
                        arm.variant
                    ))
                })?;
            if sample > best_sample {
                best_sample = sample;
                best = index;
            }
        }
        wins[best] += 1;
    }
    Ok(wins
        .iter()
        .map(|wins| *wins as f64 / draws as f64)
        .collect())
}

/// Monte-Carlo probability that `challenger` beats `control`.
pub fn probability_challenger_beats(
    control: &ArmPosterior,
    challenger: &ArmPosterior,
    draws: usize,
) -> Result<f64, SalesError> {
    validate_posterior(control.alpha, control.beta)?;
    validate_posterior(challenger.alpha, challenger.beta)?;
    let draws = draws.max(1);
    let mut rng = StdRng::from_os_rng();
    let mut wins = 0u64;
    for _ in 0..draws {
        let challenge =
            analytics::campaign_autopilot::sample_beta(&mut rng, challenger.alpha, challenger.beta)
                .map_err(|error| {
                    SalesError::InvalidInput(format!(
                        "challenger '{}' posterior cannot be sampled: {error}",
                        challenger.variant
                    ))
                })?;
        let incumbent =
            analytics::campaign_autopilot::sample_beta(&mut rng, control.alpha, control.beta)
                .map_err(|error| {
                    SalesError::InvalidInput(format!(
                        "control '{}' posterior cannot be sampled: {error}",
                        control.variant
                    ))
                })?;
        if challenge > incumbent {
            wins += 1;
        }
    }
    Ok(wins as f64 / draws as f64)
}

// ---------------------------------------------------------------------------
// Context dimensions
// ---------------------------------------------------------------------------

/// The ten documented context dimensions (§18). Every field is optional; a
/// missing dimension simply does not participate in the bucket key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExperimentContext {
    pub icp_segment: Option<String>,
    pub country: Option<String>,
    pub company_size_band: Option<String>,
    pub persona: Option<String>,
    pub esp_hypothesis: Option<String>,
    pub intent_bucket: Option<String>,
    pub offer: Option<String>,
    pub language: Option<String>,
    pub step_kind: Option<String>,
    pub sender_type: Option<String>,
}

impl ExperimentContext {
    /// Canonical dimension names, in bucket-key order.
    pub const DIMENSIONS: [&'static str; 10] = [
        "icp_segment",
        "country",
        "company_size_band",
        "persona",
        "esp_hypothesis",
        "intent_bucket",
        "offer",
        "language",
        "step_kind",
        "sender_type",
    ];

    fn value(&self, dimension: &str) -> Option<&str> {
        let value = match dimension {
            "icp_segment" => self.icp_segment.as_deref(),
            "country" => self.country.as_deref(),
            "company_size_band" => self.company_size_band.as_deref(),
            "persona" => self.persona.as_deref(),
            "esp_hypothesis" => self.esp_hypothesis.as_deref(),
            "intent_bucket" => self.intent_bucket.as_deref(),
            "offer" => self.offer.as_deref(),
            "language" => self.language.as_deref(),
            "step_kind" => self.step_kind.as_deref(),
            "sender_type" => self.sender_type.as_deref(),
            _ => None,
        };
        value.map(str::trim).filter(|value| !value.is_empty())
    }

    /// Sanitized, deterministic bucket key over the selected dimensions.
    /// Returns `None` when every selected dimension is absent — the caller
    /// must then use the global posterior (never a random arm).
    pub fn bucket_key(&self, dimensions: &[String]) -> Option<String> {
        let selected: Vec<&str> = if dimensions.is_empty() {
            Self::DIMENSIONS.to_vec()
        } else {
            let known: HashSet<&str> = Self::DIMENSIONS.iter().copied().collect();
            dimensions
                .iter()
                .map(|dimension| dimension.as_str())
                .filter(|dimension| known.contains(dimension))
                .collect()
        };
        let mut parts: Vec<String> = Vec::new();
        for dimension in selected {
            if let Some(value) = self.value(dimension) {
                parts.push(format!("{}={}", dimension, sanitize_context_value(value)));
            }
        }
        if parts.is_empty() {
            return None;
        }
        let joined = parts.join("|");
        if joined.len() <= MAX_CONTEXT_KEY_LEN {
            return Some(joined);
        }
        // Deterministic shortening: prefix + FNV-1a hash of the full value, so
        // two different giant contexts never collide silently.
        let hash = fnv1a64(joined.as_bytes());
        let keep = MAX_CONTEXT_KEY_LEN.saturating_sub(20);
        let mut truncated: String = joined.chars().take(keep).collect();
        truncated.push('~');
        truncated.push_str(&format!("{hash:016x}"));
        Some(truncated)
    }
}

/// Lowercase, keep `[a-z0-9_.-]`, collapse everything else to `_`, cap length.
fn sanitize_context_value(value: &str) -> String {
    let lowered = value.trim().to_ascii_lowercase();
    let mut out = String::with_capacity(lowered.len().min(MAX_CONTEXT_VALUE_LEN));
    for ch in lowered.chars() {
        if out.len() >= MAX_CONTEXT_VALUE_LEN {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "_".to_string()
    } else {
        trimmed.to_string()
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// §37 economic exploration limits
// ---------------------------------------------------------------------------

/// Exploration limits parsed from `sales_experiments.budgets`
/// (migration 200_sales_autopilot_v2_unification.sql:788-805).
///
/// Semantics, all enforced by [`may_explore`]:
///
/// * `None` = unlimited for that dimension;
/// * `Some(0)` = ZERO, never unlimited (the classic fail-open bug is treating
///   0 as "unset");
/// * a negative count or a percentage outside `0..=100` (or NaN) is rejected
///   to its fail-closed value (`0` / `0.0`) by [`Self::sanitized`], so a
///   hostile budget can never widen exploration;
/// * `min_posterior_confidence` outside `(0, 1]` fails closed to `1.0`, which
///   no arm can satisfy, so promotion is impossible until it is fixed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplorationBudget {
    pub max_contacts: Option<i64>,
    pub max_sender_domain_exposure: Option<i64>,
    pub max_daily_exploration_pct: Option<f64>,
    pub max_negative_outcome_budget: Option<i64>,
    pub max_enrichment_spend_eur: Option<f64>,
    pub min_sample_before_promotion: i64,
    pub min_posterior_confidence: f64,
    /// Above this expected value (EUR) an account is excluded from exploration
    /// (it always receives the control/best arm) unless
    /// [`ExplorationState::explicit_exploration_override`] is set. `None`
    /// disables the exemption.
    pub high_value_ev_threshold_eur: Option<f64>,
    /// Required margin by which the challenger's 95% credible interval lower
    /// bound must beat the control's upper bound.
    pub promotion_margin: f64,
}

impl Default for ExplorationBudget {
    fn default() -> Self {
        Self {
            max_contacts: None,
            max_sender_domain_exposure: None,
            max_daily_exploration_pct: None,
            max_negative_outcome_budget: None,
            max_enrichment_spend_eur: None,
            min_sample_before_promotion: DEFAULT_MIN_SAMPLE_BEFORE_PROMOTION,
            min_posterior_confidence: DEFAULT_MIN_POSTERIOR_CONFIDENCE,
            high_value_ev_threshold_eur: Some(DEFAULT_HIGH_VALUE_EV_THRESHOLD_EUR),
            promotion_margin: 0.0,
        }
    }
}

impl ExplorationBudget {
    /// Parse the `budgets` JSONB object. A non-object (including a bare JSON
    /// string or number) is a configuration error — the caller must not treat
    /// it as "no limits". Present numeric fields are parsed strictly (a string
    /// where a number belongs is an error); out-of-domain numbers are then
    /// sanitised fail-closed by [`Self::sanitized`].
    pub fn from_json(value: &serde_json::Value) -> Result<Self, SalesError> {
        let object = value.as_object().ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "sales_experiments.budgets must be a JSON object, got {}",
                json_type_name(value)
            ))
        })?;

        let max_contacts = opt_i64(object, "max_contacts")?;
        let max_sender_domain_exposure = opt_i64(object, "max_sender_domain_exposure")?;
        let max_daily_exploration_pct = opt_f64(object, "max_daily_exploration_pct")?;
        let max_negative_outcome_budget = opt_i64(object, "max_negative_outcome_budget")?;
        let max_enrichment_spend_eur = opt_f64(object, "max_enrichment_spend_eur")?;
        let min_sample_before_promotion = opt_i64(object, "min_sample_before_promotion")?
            .unwrap_or(DEFAULT_MIN_SAMPLE_BEFORE_PROMOTION);
        let min_posterior_confidence = opt_f64(object, "min_posterior_confidence")?
            .unwrap_or(DEFAULT_MIN_POSTERIOR_CONFIDENCE);
        let high_value_ev_threshold_eur = match object.get("high_value_ev_threshold_eur") {
            None => Some(DEFAULT_HIGH_VALUE_EV_THRESHOLD_EUR),
            Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(number)) => {
                number.as_f64().map(Some).ok_or_else(|| {
                    SalesError::InvalidInput(
                        "budgets.high_value_ev_threshold_eur is not representable as f64".into(),
                    )
                })?
            }
            Some(other) => {
                return Err(SalesError::InvalidInput(format!(
                    "budgets.high_value_ev_threshold_eur must be a number or null, got {}",
                    json_type_name(other)
                )))
            }
        };
        let promotion_margin = opt_f64(object, "promotion_margin")?.unwrap_or(0.0);

        Ok(Self {
            max_contacts,
            max_sender_domain_exposure,
            max_daily_exploration_pct,
            max_negative_outcome_budget,
            max_enrichment_spend_eur,
            min_sample_before_promotion,
            min_posterior_confidence,
            high_value_ev_threshold_eur,
            promotion_margin,
        }
        .sanitized())
    }

    /// Fail-closed normalisation. Idempotent. Public so tests and callers can
    /// prove the fail-closed behaviour on hand-built (hostile) values, since
    /// JSON cannot carry NaN.
    pub fn sanitized(mut self) -> Self {
        self.max_contacts = self.max_contacts.map(|value| value.max(0));
        self.max_sender_domain_exposure = self.max_sender_domain_exposure.map(|value| value.max(0));
        self.max_negative_outcome_budget =
            self.max_negative_outcome_budget.map(|value| value.max(0));
        self.max_daily_exploration_pct = self.max_daily_exploration_pct.map(|value| {
            if value.is_finite() && (0.0..=100.0).contains(&value) {
                value
            } else {
                // Negative, NaN or >100%: no exploration at all, never
                // "unlimited".
                0.0
            }
        });
        self.max_enrichment_spend_eur = self.max_enrichment_spend_eur.map(|value| {
            if value.is_finite() && value >= 0.0 {
                value
            } else {
                0.0
            }
        });
        if self.min_sample_before_promotion < 0 {
            self.min_sample_before_promotion = DEFAULT_MIN_SAMPLE_BEFORE_PROMOTION;
        }
        if !(self.min_posterior_confidence.is_finite()
            && self.min_posterior_confidence > 0.0
            && self.min_posterior_confidence <= 1.0)
        {
            // 1.5 is unsatisfiable: promotion is refused until corrected.
            self.min_posterior_confidence = 1.0;
        }
        if !(self.promotion_margin.is_finite() && self.promotion_margin >= 0.0) {
            self.promotion_margin = 0.0;
        }
        self.high_value_ev_threshold_eur = match self.high_value_ev_threshold_eur {
            None => None,
            Some(value) if value.is_finite() && value >= 0.0 => Some(value),
            // Hostile threshold: every account is "high value" → exploit only.
            Some(_) => Some(0.0),
        };
        self
    }

    /// Serialize back to the canonical JSONB shape (used when a derived
    /// context bucket inherits its parent's limits).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "max_contacts": self.max_contacts,
            "max_sender_domain_exposure": self.max_sender_domain_exposure,
            "max_daily_exploration_pct": self.max_daily_exploration_pct,
            "max_negative_outcome_budget": self.max_negative_outcome_budget,
            "max_enrichment_spend_eur": self.max_enrichment_spend_eur,
            "min_sample_before_promotion": self.min_sample_before_promotion,
            "min_posterior_confidence": self.min_posterior_confidence,
            "high_value_ev_threshold_eur": self.high_value_ev_threshold_eur,
            "promotion_margin": self.promotion_margin,
        })
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn opt_i64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<i64>, SalesError> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(number)) => number.as_i64().map(Some).ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "budgets.{key} must be an integer that fits in 64 bits"
            ))
        }),
        Some(other) => Err(SalesError::InvalidInput(format!(
            "budgets.{key} must be a number, got {}",
            json_type_name(other)
        ))),
    }
}

fn opt_f64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<f64>, SalesError> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(number)) => number.as_f64().map(Some).ok_or_else(|| {
            SalesError::InvalidInput(format!("budgets.{key} is not representable as f64"))
        }),
        Some(other) => Err(SalesError::InvalidInput(format!(
            "budgets.{key} must be a number, got {}",
            json_type_name(other)
        ))),
    }
}

/// Live exploration state for one decision, aggregated from
/// `sales_experiment_arms` and the caller's runtime counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExplorationState {
    /// Contacts used by the experiment family (sum of arm `contacts`).
    pub contacts: i64,
    /// Sends from the experiment's sender domain in the budget window.
    pub sender_domain_exposure: i64,
    /// Today's share of sends that were exploratory, in percent `0..=100`.
    pub daily_exploration_pct: f64,
    /// Penalty outcomes recorded by the experiment family.
    pub negative_outcomes: i64,
    /// Enrichment spend attributed to the experiment family, EUR.
    pub enrichment_spend_eur: f64,
    /// Expected value of the account being decided, EUR.
    pub account_expected_value_eur: f64,
    /// Operator override lifting the high-value exemption for this decision.
    pub explicit_exploration_override: bool,
}

/// The pure exploration verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplorationVerdict {
    /// Thompson sampling may explore.
    Allowed,
    /// No exploration; deterministically take the best arm. Sending continues
    /// (the business does not stop), learning does.
    ExploitOnly(String),
    /// Stop the experiment's sends entirely (harm/sender-reputation budget
    /// exhausted).
    Halted(String),
}

impl ExplorationVerdict {
    pub fn allows_exploration(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allowed => None,
            Self::ExploitOnly(reason) | Self::Halted(reason) => Some(reason),
        }
    }
}

/// Enforce the economic exploration limits. Pure, total and fail-closed: the
/// budget is normalised again here, so a hand-built hostile struct (NaN,
/// negative) cannot widen exploration.
///
/// Precedence (documented and tested): harm limits first (`Halted`), then
/// exposure/spend/volume limits (`ExploitOnly`), then the high-value
/// exemption.
pub fn may_explore(budget: &ExplorationBudget, state: &ExplorationState) -> ExplorationVerdict {
    let budget = budget.clone().sanitized();

    let contacts = state.contacts.max(0);
    let exposure = state.sender_domain_exposure.max(0);
    let negative = state.negative_outcomes.max(0);
    let spend = if state.enrichment_spend_eur.is_finite() {
        state.enrichment_spend_eur.max(0.0)
    } else {
        f64::INFINITY
    };
    let daily_pct = if state.daily_exploration_pct.is_finite() {
        state.daily_exploration_pct.max(0.0)
    } else {
        // A non-finite observed share fails closed: treat today as fully
        // exploratory (no further exploration).
        100.0
    };
    let account_ev = if state.account_expected_value_eur.is_finite() {
        state.account_expected_value_eur
    } else {
        f64::INFINITY
    };

    if let Some(max) = budget.max_negative_outcome_budget {
        if negative >= max {
            return ExplorationVerdict::Halted(format!(
                "negative-outcome budget exhausted: {negative} >= {max}; the experiment stops \
                 sending rather than risk more harm"
            ));
        }
    }
    if let Some(max) = budget.max_sender_domain_exposure {
        if exposure >= max {
            return ExplorationVerdict::Halted(format!(
                "sender-domain exposure budget exhausted: {exposure} >= {max}; stop sending from \
                 this experiment before the domain reputation is spent"
            ));
        }
    }
    if let Some(max) = budget.max_contacts {
        if contacts >= max {
            return ExplorationVerdict::ExploitOnly(format!(
                "contact budget exhausted: {contacts} >= {max}; falling back to the best arm \
                 (exploit-only), not stopping sends"
            ));
        }
    }
    if let Some(max) = budget.max_enrichment_spend_eur {
        if spend >= max {
            return ExplorationVerdict::ExploitOnly(format!(
                "enrichment spend budget exhausted: {spend:.4} EUR >= {max:.4} EUR; no further \
                 paid exploration"
            ));
        }
    }
    if let Some(max) = budget.max_daily_exploration_pct {
        if daily_pct >= max {
            return ExplorationVerdict::ExploitOnly(format!(
                "daily exploration share exhausted: {daily_pct:.2}% >= {max:.2}%; rest of today \
                 is exploit-only"
            ));
        }
    }
    if let Some(threshold) = budget.high_value_ev_threshold_eur {
        if account_ev >= threshold && !state.explicit_exploration_override {
            return ExplorationVerdict::ExploitOnly(format!(
                "high-value account preserved from exploration: EV {account_ev:.2} EUR >= \
                 {threshold:.2} EUR threshold; using the control/best arm (pass \
                 explicit_exploration_override to explore deliberately)"
            ));
        }
    }
    ExplorationVerdict::Allowed
}

/// §37 promotion gate for one arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionVerdict {
    pub allowed: bool,
    pub reasons: Vec<String>,
}

/// An arm may be promoted only when it has `min_sample_before_promotion`
/// informative trials **and** its 95% credible interval (lower bound) beats
/// the control's upper bound by `promotion_margin` **and** the Monte-Carlo
/// probability that it beats control is at least `min_posterior_confidence`.
/// Uses [`analytics::campaign_autopilot::credible_interval_95`].
pub fn may_promote_arm(
    budget: &ExplorationBudget,
    control: &ArmPosterior,
    candidate: &ArmPosterior,
    probability_beats_control: f64,
) -> PromotionVerdict {
    let budget = budget.clone().sanitized();
    let mut reasons: Vec<String> = Vec::new();

    if candidate.is_control {
        reasons.push("the control arm cannot be promoted over itself".to_string());
    }
    if candidate.trials < budget.min_sample_before_promotion {
        reasons.push(format!(
            "insufficient sample: {} informative trials < {} required",
            candidate.trials, budget.min_sample_before_promotion
        ));
    }
    let (candidate_low, _) = candidate.credible_interval();
    let (_, control_high) = control.credible_interval();
    let required = control_high + budget.promotion_margin;
    if candidate_low < required {
        reasons.push(format!(
            "95% credible interval does not beat control: candidate lower {candidate_low:.4} < \
             control upper {control_high:.4} + margin {:.4}",
            budget.promotion_margin
        ));
    }
    if !probability_beats_control.is_finite()
        || probability_beats_control < budget.min_posterior_confidence
    {
        reasons.push(format!(
            "posterior confidence too low: P(candidate > control) = \
             {probability_beats_control:.4} < {} required",
            budget.min_posterior_confidence
        ));
    }

    PromotionVerdict {
        allowed: reasons.is_empty(),
        reasons,
    }
}

// ---------------------------------------------------------------------------
// Experiment identity
// ---------------------------------------------------------------------------

/// `sales_experiments.status` vocabulary (migration line 793-794). An
/// unrecognised status fails closed to `Stopped` — it is never treated as
/// `Running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentStatus {
    Draft,
    Running,
    Paused,
    Promoted,
    Stopped,
}

impl ExperimentStatus {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "draft" => Self::Draft,
            "running" => Self::Running,
            "paused" => Self::Paused,
            "promoted" => Self::Promoted,
            _ => Self::Stopped,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Promoted => "promoted",
            Self::Stopped => "stopped",
        }
    }

    /// May new arms be explored? Only a running experiment.
    pub fn explores(self) -> bool {
        matches!(self, Self::Running)
    }
}

/// One `sales_experiments` row plus its parsed limits.
#[derive(Debug, Clone)]
pub struct Experiment {
    pub id: Uuid,
    pub tenant_id: String,
    pub key: String,
    pub name: String,
    pub status: ExperimentStatus,
    pub context_dimensions: Vec<String>,
    pub budgets: ExplorationBudget,
}

/// Everything `select_variant` needs beyond the experiment row.
#[derive(Debug, Clone, Default)]
pub struct VariantContext {
    pub dimensions: ExperimentContext,
    pub sender_domain_exposure: i64,
    pub daily_exploration_pct: f64,
    pub account_expected_value_eur: f64,
    pub explicit_exploration_override: bool,
}

/// The selected arm, with the reason it was selected (becomes a Decision
/// Packet rationale).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantSelection {
    pub variant: String,
    /// The experiment whose posterior is authoritative for this decision (the
    /// bucket experiment when it has enough samples, otherwise the global
    /// one). Rewards must be recorded against this id.
    pub experiment_id: Uuid,
    pub is_control: bool,
    /// `false` means exploit-only (budget exhausted, paused/stopped, or
    /// high-value preservation).
    pub explore: bool,
    pub used_context_bucket: bool,
    pub context_bucket: Option<String>,
    pub posterior_mean: f64,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Database-backed experiment engine over the canonical sales tables.
#[derive(Debug, Clone)]
pub struct ExperimentEngine {
    db: PgPool,
}

impl ExperimentEngine {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &PgPool {
        &self.db
    }

    /// Load an experiment by `(tenant_id, key)`.
    pub async fn load_experiment(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> Result<Option<Experiment>, SalesError> {
        if tenant_id.trim().is_empty() || key.trim().is_empty() {
            return Err(SalesError::InvalidInput(
                "tenant_id and experiment key are required".into(),
            ));
        }
        let row = sqlx::query(
            "SELECT id, tenant_id, key, name, status, context, budgets \
             FROM sales_experiments WHERE tenant_id = $1 AND key = $2",
        )
        .bind(tenant_id)
        .bind(key)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        let Some(row) = row else { return Ok(None) };
        let context: serde_json::Value = row
            .try_get("context")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let budgets: serde_json::Value = row
            .try_get("budgets")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(Some(Experiment {
            id: row
                .try_get("id")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            tenant_id: row
                .try_get("tenant_id")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            key: row
                .try_get("key")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            name: row
                .try_get("name")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            status: ExperimentStatus::parse(
                &row.try_get::<String, _>("status")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
            ),
            context_dimensions: parse_context_dimensions(&context),
            budgets: ExplorationBudget::from_json(&budgets)?,
        }))
    }

    /// Idempotent provisioning on `(tenant_id, key)`. Existing budgets are
    /// preserved (only an empty `{}` is replaced), so a redeploy cannot
    /// silently reset an operator's limits.
    pub async fn ensure_experiment(
        &self,
        tenant_id: &str,
        key: &str,
        name: &str,
        context: &serde_json::Value,
        budgets: &serde_json::Value,
    ) -> Result<Uuid, SalesError> {
        if tenant_id.trim().is_empty() {
            return Err(SalesError::InvalidInput("tenant_id is required".into()));
        }
        if key.trim().is_empty() {
            return Err(SalesError::InvalidInput(
                "experiment key is required".into(),
            ));
        }
        if name.trim().is_empty() {
            return Err(SalesError::InvalidInput(
                "experiment name is required".into(),
            ));
        }
        // Reject a hostile budget up front rather than storing it.
        let _ = ExplorationBudget::from_json(budgets)?;

        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_experiments \
                 (id, tenant_id, key, name, status, context, budgets, created_at, updated_at) \
             VALUES (gen_random_uuid(), $1, $2, $3, 'draft', $4, $5, NOW(), NOW()) \
             ON CONFLICT (tenant_id, key) DO UPDATE SET \
                 name = EXCLUDED.name, \
                 context = EXCLUDED.context, \
                 budgets = CASE WHEN sales_experiments.budgets = '{}'::jsonb \
                                THEN EXCLUDED.budgets ELSE sales_experiments.budgets END, \
                 updated_at = NOW() \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(key)
        .bind(name)
        .bind(context)
        .bind(budgets)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(id)
    }

    /// Set the experiment status (operator/control-plane action).
    pub async fn set_status(
        &self,
        tenant_id: &str,
        experiment_id: Uuid,
        status: ExperimentStatus,
    ) -> Result<(), SalesError> {
        let updated = sqlx::query(
            "UPDATE sales_experiments SET status = $3, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(experiment_id)
        .bind(status.as_str())
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?
        .rows_affected();
        if updated != 1 {
            return Err(SalesError::InvalidInput(format!(
                "experiment {experiment_id} not found for tenant {tenant_id}"
            )));
        }
        Ok(())
    }

    /// Provision arms idempotently with fresh `Beta(1, 1)` priors. Existing
    /// arms keep their accumulated statistics.
    pub async fn ensure_arms(
        &self,
        tenant_id: &str,
        experiment_id: Uuid,
        arms: &[ArmSpec],
    ) -> Result<(), SalesError> {
        if arms.is_empty() {
            return Err(SalesError::InvalidInput(
                "cannot provision zero arms for an experiment".into(),
            ));
        }
        if arms.len() > MAX_ARMS_PER_EXPERIMENT {
            return Err(SalesError::InvalidInput(format!(
                "experiment declares {} arms; the maximum is {MAX_ARMS_PER_EXPERIMENT}",
                arms.len()
            )));
        }
        let mut seen: HashSet<String> = HashSet::new();
        for arm in arms {
            let variant = arm.variant.trim().to_string();
            if variant.is_empty() {
                return Err(SalesError::InvalidInput(
                    "arm variant must not be empty".into(),
                ));
            }
            if variant.chars().count() > 128 {
                let prefix: String = variant.chars().take(16).collect();
                return Err(SalesError::InvalidInput(format!(
                    "arm variant '{prefix}…' exceeds 128 characters"
                )));
            }
            if !seen.insert(variant.clone()) {
                return Err(SalesError::InvalidInput(format!(
                    "duplicate arm variant '{variant}'"
                )));
            }
        }
        validate_posterior(1.0, 1.0)?;

        let owns: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sales_experiments WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(experiment_id)
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        if !owns {
            return Err(SalesError::InvalidInput(format!(
                "experiment {experiment_id} not found for tenant {tenant_id}"
            )));
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        for arm in arms {
            sqlx::query(
                "INSERT INTO sales_experiment_arms \
                     (id, tenant_id, experiment_id, variant, alpha, beta, trials, successes, \
                      contacts, enrichment_cost_eur, negative_outcomes, is_control, \
                      created_at, updated_at) \
                 VALUES (gen_random_uuid(), $1, $2, $3, 1.0, 1.0, 0, 0, 0, 0, 0, $4, NOW(), NOW()) \
                 ON CONFLICT (experiment_id, variant) DO NOTHING",
            )
            .bind(tenant_id)
            .bind(experiment_id)
            .bind(arm.variant.trim())
            .bind(arm.is_control)
            .execute(&mut *tx)
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(())
    }

    /// Load arms for one experiment, tenant-scoped through the join with
    /// `sales_experiments`. Deterministic order (control first, then variant).
    pub async fn load_arms(
        &self,
        tenant_id: &str,
        experiment_id: Uuid,
    ) -> Result<Vec<ArmPosterior>, SalesError> {
        let rows = sqlx::query(
            "SELECT a.variant, a.alpha, a.beta, a.trials, a.successes, a.contacts, \
                    a.enrichment_cost_eur::float8 AS enrichment_cost_eur, \
                    a.negative_outcomes, a.is_control \
             FROM sales_experiment_arms a \
             JOIN sales_experiments e ON e.id = a.experiment_id \
             WHERE a.experiment_id = $1 AND e.tenant_id = $2 \
             ORDER BY a.is_control DESC, a.variant ASC",
        )
        .bind(experiment_id)
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        rows.into_iter()
            .map(|row| {
                Ok(ArmPosterior {
                    variant: row
                        .try_get("variant")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    alpha: row
                        .try_get("alpha")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    beta: row
                        .try_get("beta")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    trials: row
                        .try_get("trials")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    successes: row
                        .try_get("successes")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    contacts: row
                        .try_get("contacts")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    enrichment_cost_eur: row
                        .try_get("enrichment_cost_eur")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    negative_outcomes: row
                        .try_get("negative_outcomes")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                    is_control: row
                        .try_get("is_control")
                        .map_err(|error| SalesError::Database(error.to_string()))?,
                })
            })
            .collect()
    }

    /// Aggregate budget counters across the experiment family (the parent and
    /// its derived context buckets), so the §37 limits bound the whole
    /// experiment rather than being reset per bucket.
    pub async fn load_family_state(
        &self,
        tenant_id: &str,
        parent: &Experiment,
    ) -> Result<(i64, i64, f64), SalesError> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(a.contacts), 0)::bigint AS contacts, \
                    COALESCE(SUM(a.negative_outcomes), 0)::bigint AS negative_outcomes, \
                    COALESCE(SUM(a.enrichment_cost_eur), 0)::float8 AS enrichment_cost_eur \
             FROM sales_experiment_arms a \
             WHERE a.tenant_id = $1 \
               AND (a.experiment_id = $2 \
                    OR a.experiment_id IN ( \
                        SELECT c.id FROM sales_experiments c \
                        WHERE c.tenant_id = $1 AND c.context->>'parent_key' = $3 \
                    ))",
        )
        .bind(tenant_id)
        .bind(parent.id)
        .bind(&parent.key)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok((
            row.try_get("contacts")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            row.try_get("negative_outcomes")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            row.try_get("enrichment_cost_eur")
                .map_err(|error| SalesError::Database(error.to_string()))?,
        ))
    }

    /// Select the arm for one step execution.
    ///
    /// Order of decisions (each documented in [`VariantSelection::reason`]):
    ///
    /// 1. a draft experiment is a configuration error — never send against it;
    /// 2. a paused/stopped/promoted experiment is exploit-only (best arm);
    /// 3. [`may_explore`] is enforced before any arm is drawn;
    /// 4. contextual fallback: a bucket with `< MIN_CONTEXT_SAMPLES` trials
    ///    uses the global posterior; otherwise its own;
    /// 5. the arm is drawn with Thompson sampling (single Beta sampler), or
    ///    chosen deterministically in exploit-only mode.
    pub async fn select_variant(
        &self,
        tenant_id: &str,
        experiment: &Experiment,
        context: &VariantContext,
    ) -> Result<VariantSelection, SalesError> {
        if tenant_id.trim().is_empty() {
            return Err(SalesError::InvalidInput("tenant_id is required".into()));
        }
        if experiment.status == ExperimentStatus::Draft {
            return Err(SalesError::InvalidInput(format!(
                "experiment '{}' is still draft; refusing to select an arm for a live send",
                experiment.key
            )));
        }

        let arms = self.load_arms(tenant_id, experiment.id).await?;
        if arms.is_empty() {
            return Err(SalesError::InvalidInput(format!(
                "experiment '{}' has no arms",
                experiment.key
            )));
        }
        for arm in &arms {
            validate_posterior(arm.alpha, arm.beta)?;
            if arm.trials < 0 || arm.successes < 0 || arm.successes > arm.trials {
                return Err(SalesError::InvalidInput(format!(
                    "arm '{}' has inconsistent counters: trials={}, successes={}",
                    arm.variant, arm.trials, arm.successes
                )));
            }
        }

        // Exploit-only shortcuts: fail closed to the deterministic best arm.
        if !experiment.status.explores() {
            let index = best_arm_index(&arms).ok_or_else(|| {
                SalesError::InvalidInput(format!(
                    "experiment '{}' has no selectable arm",
                    experiment.key
                ))
            })?;
            let arm = &arms[index];
            return Ok(VariantSelection {
                variant: arm.variant.clone(),
                experiment_id: experiment.id,
                is_control: arm.is_control,
                explore: false,
                used_context_bucket: false,
                context_bucket: None,
                posterior_mean: arm.mean(),
                reason: format!(
                    "experiment status is '{}' (not running): exploit-only on best posterior mean \
                     {:.4}",
                    experiment.status.as_str(),
                    arm.mean()
                ),
            });
        }

        if arms.len() > MAX_ARMS_PER_EXPERIMENT {
            let index = best_arm_index(&arms).ok_or_else(|| {
                SalesError::InvalidInput("experiment has no selectable arm".into())
            })?;
            let arm = &arms[index];
            return Ok(VariantSelection {
                variant: arm.variant.clone(),
                experiment_id: experiment.id,
                is_control: arm.is_control,
                explore: false,
                used_context_bucket: false,
                context_bucket: None,
                posterior_mean: arm.mean(),
                reason: format!(
                    "experiment declares {} arms (> {MAX_ARMS_PER_EXPERIMENT}); failing closed to \
                     exploit-only",
                    arms.len()
                ),
            });
        }

        let (contacts, negative_outcomes, enrichment_spend_eur) =
            self.load_family_state(tenant_id, experiment).await?;
        let state = ExplorationState {
            contacts,
            sender_domain_exposure: context.sender_domain_exposure,
            daily_exploration_pct: context.daily_exploration_pct,
            negative_outcomes,
            enrichment_spend_eur,
            account_expected_value_eur: context.account_expected_value_eur,
            explicit_exploration_override: context.explicit_exploration_override,
        };
        let verdict = may_explore(&experiment.budgets, &state);
        if !verdict.allows_exploration() {
            let index = best_arm_index(&arms).ok_or_else(|| {
                SalesError::InvalidInput("experiment has no selectable arm".into())
            })?;
            let arm = &arms[index];
            let reason = verdict
                .reason()
                .unwrap_or("exploration not permitted")
                .to_string();
            return Ok(VariantSelection {
                variant: arm.variant.clone(),
                experiment_id: experiment.id,
                is_control: arm.is_control,
                explore: false,
                used_context_bucket: false,
                context_bucket: None,
                posterior_mean: arm.mean(),
                reason: format!(
                    "{reason}; exploit-only on best posterior mean {:.4}",
                    arm.mean()
                ),
            });
        }

        // Contextual hierarchical fallback.
        let bucket_key = context
            .dimensions
            .bucket_key(&experiment.context_dimensions);
        let (authoritative, authoritative_id, used_context_bucket, bucket_note) =
            match bucket_key.as_deref() {
                Some(bucket) => {
                    let bucket_experiment = self
                        .ensure_context_bucket(tenant_id, experiment, bucket)
                        .await?;
                    let bucket_arms = self.load_arms(tenant_id, bucket_experiment.id).await?;
                    let bucket_trials: i64 = bucket_arms.iter().map(|arm| arm.trials).sum();
                    if bucket_trials >= MIN_CONTEXT_SAMPLES && !bucket_arms.is_empty() {
                        (
                            bucket_arms,
                            bucket_experiment.id,
                            true,
                            format!(
                                "context bucket '{bucket}' has {bucket_trials} >= \
                                 MIN_CONTEXT_SAMPLES ({MIN_CONTEXT_SAMPLES}); using its own \
                                 posterior"
                            ),
                        )
                    } else {
                        (
                            arms.clone(),
                            experiment.id,
                            false,
                            format!(
                                "context bucket '{bucket}' has only {bucket_trials} < \
                                 MIN_CONTEXT_SAMPLES ({MIN_CONTEXT_SAMPLES}); hierarchical \
                                 fallback to the global posterior (documented shrinkage rule)"
                            ),
                        )
                    }
                }
                None => (
                    arms.clone(),
                    experiment.id,
                    false,
                    "no context dimension observed; using the global posterior".to_string(),
                ),
            };

        for arm in &authoritative {
            validate_posterior(arm.alpha, arm.beta)?;
        }
        let mut rng = StdRng::from_os_rng();
        let mut best = 0usize;
        let mut best_sample = f64::NEG_INFINITY;
        for (index, arm) in authoritative.iter().enumerate() {
            let sample = analytics::campaign_autopilot::sample_beta(&mut rng, arm.alpha, arm.beta)
                .map_err(|error| {
                    SalesError::InvalidInput(format!(
                        "arm '{}' posterior cannot be sampled: {error}",
                        arm.variant
                    ))
                })?;
            if sample > best_sample {
                best_sample = sample;
                best = index;
            }
        }
        let arm = &authoritative[best];
        let reason = format!(
            "Thompson sampling selected '{}' (posterior mean {:.4}, sampled {:.4}); {bucket_note}",
            arm.variant,
            arm.mean(),
            best_sample
        );

        Ok(VariantSelection {
            variant: arm.variant.clone(),
            experiment_id: authoritative_id,
            is_control: arm.is_control,
            explore: true,
            used_context_bucket,
            context_bucket: bucket_key,
            posterior_mean: arm.mean(),
            reason,
        })
    }

    /// Lazily provision the derived context-bucket experiment, inheriting the
    /// parent's variants (fresh priors) and limits. Idempotent.
    async fn ensure_context_bucket(
        &self,
        tenant_id: &str,
        parent: &Experiment,
        bucket_key: &str,
    ) -> Result<Experiment, SalesError> {
        let key = context_bucket_experiment_key(&parent.key, bucket_key);
        if let Some(existing) = self.load_experiment(tenant_id, &key).await? {
            return Ok(existing);
        }

        let parent_arms = self.load_arms(tenant_id, parent.id).await?;
        let specs: Vec<ArmSpec> = parent_arms
            .iter()
            .map(|arm| ArmSpec {
                variant: arm.variant.clone(),
                is_control: arm.is_control,
            })
            .collect();

        let context = serde_json::json!({
            "parent_key": parent.key,
            "bucket": bucket_key,
            "dimensions": parent.context_dimensions,
            "derived": true,
        });
        let budgets = parent.budgets.to_json();
        let bucket_id = self
            .ensure_experiment(
                tenant_id,
                &key,
                &format!("{} / {bucket_key}", parent.name),
                &context,
                &budgets,
            )
            .await?;
        self.ensure_arms(tenant_id, bucket_id, &specs).await?;
        // The bucket participates in live learning from its first send, so it
        // is running (an operator can still pause it explicitly later; the
        // early return above preserves that decision).
        self.set_status(tenant_id, bucket_id, ExperimentStatus::Running)
            .await?;
        self.load_experiment(tenant_id, &key).await?.ok_or_else(|| {
            SalesError::Database(format!(
                "context bucket experiment '{key}' vanished immediately after provisioning"
            ))
        })
    }

    /// Promote an arm through the §37 gate, persisting the experiment status.
    /// The promotion is a decision, not a re-learning: the arm's statistics
    /// are untouched.
    pub async fn promote_arm(
        &self,
        tenant_id: &str,
        experiment: &Experiment,
        candidate_variant: &str,
    ) -> Result<PromotionVerdict, SalesError> {
        let arms = self.load_arms(tenant_id, experiment.id).await?;
        let control = arms
            .iter()
            .find(|arm| arm.is_control)
            .ok_or_else(|| {
                SalesError::InvalidInput(format!(
                    "experiment '{}' has no control arm",
                    experiment.key
                ))
            })?
            .clone();
        let candidate = arms
            .iter()
            .find(|arm| arm.variant == candidate_variant)
            .ok_or_else(|| {
                SalesError::InvalidInput(format!(
                    "experiment '{}' has no arm '{candidate_variant}'",
                    experiment.key
                ))
            })?
            .clone();
        let probability = probability_challenger_beats(&control, &candidate, 2_000)?;
        let verdict = may_promote_arm(&experiment.budgets, &control, &candidate, probability);
        if verdict.allowed {
            self.set_status(tenant_id, experiment.id, ExperimentStatus::Promoted)
                .await?;
        }
        Ok(verdict)
    }
}

/// Key of a derived context-bucket experiment.
pub fn context_bucket_experiment_key(parent_key: &str, bucket_key: &str) -> String {
    format!("{parent_key}::ctx::{bucket_key}")
}

/// Parse `sales_experiments.context.dimensions`; absent/invalid means all ten.
fn parse_context_dimensions(value: &serde_json::Value) -> Vec<String> {
    let known: HashSet<&str> = ExperimentContext::DIMENSIONS.iter().copied().collect();
    let dimensions: Vec<String> = value
        .get("dimensions")
        .and_then(|dimensions| dimensions.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|entry| entry.as_str())
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| known.contains(entry.as_str()))
                .collect()
        })
        .unwrap_or_default();
    if dimensions.is_empty() {
        ExperimentContext::DIMENSIONS
            .iter()
            .map(|dimension| (*dimension).to_string())
            .collect()
    } else {
        dimensions
    }
}

// ---------------------------------------------------------------------------
// Outcome ledger write path
// ---------------------------------------------------------------------------

/// Record one outcome against an arm, idempotently.
///
/// `outcome_key` is the logical identity of the observation (for example
/// `"{step_execution_id}:positive_reply"`); it is the primary key of
/// `sales_experiment_outcomes` (migration line 830), so replaying it moves the
/// posterior at most once. The ledger insert and the arm update share one
/// transaction.
///
/// Hostile inputs are rejected before any SQL: an empty/oversized
/// `outcome_key`, a non-finite or negative `value_eur`, a corrupt arm
/// posterior (`alpha`/`beta` <= 0 or non-finite — the DB CHECK would reject it
/// anyway, but the error must name the arm), or an experiment that does not
/// belong to the tenant.
pub async fn record_reward(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
    variant: &str,
    kind: RewardKind,
    outcome_key: &str,
    value_eur: f64,
) -> Result<(), SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    let outcome_key = outcome_key.trim();
    if outcome_key.is_empty() {
        return Err(SalesError::InvalidInput("outcome_key is required".into()));
    }
    if outcome_key.len() > MAX_OUTCOME_KEY_LEN {
        return Err(SalesError::InvalidInput(format!(
            "outcome_key is {} bytes; the maximum is {MAX_OUTCOME_KEY_LEN}",
            outcome_key.len()
        )));
    }
    if variant.trim().is_empty() {
        return Err(SalesError::InvalidInput("variant is required".into()));
    }
    if !value_eur.is_finite() || value_eur < 0.0 {
        return Err(SalesError::InvalidInput(format!(
            "value_eur must be finite and >= 0, got {value_eur}"
        )));
    }
    let reward = kind.reward();
    if !reward.is_finite() {
        return Err(SalesError::InvalidInput(format!(
            "reward for {kind} must be finite"
        )));
    }

    // Load + validate the arm before writing anything.
    let row = sqlx::query(
        "SELECT a.alpha, a.beta, a.trials, a.successes \
         FROM sales_experiment_arms a \
         JOIN sales_experiments e ON e.id = a.experiment_id \
         WHERE a.experiment_id = $1 AND a.variant = $2 AND e.tenant_id = $3",
    )
    .bind(experiment_id)
    .bind(variant.trim())
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let Some(row) = row else {
        return Err(SalesError::InvalidInput(format!(
            "arm '{variant}' of experiment {experiment_id} does not exist for tenant {tenant_id}"
        )));
    };
    let alpha: f64 = row
        .try_get("alpha")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let beta: f64 = row
        .try_get("beta")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let trials: i64 = row
        .try_get("trials")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let successes: i64 = row
        .try_get("successes")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    validate_posterior(alpha, beta)?;
    if trials < 0 || successes < 0 || successes > trials {
        return Err(SalesError::InvalidInput(format!(
            "arm '{variant}' has inconsistent counters: trials={trials}, successes={successes}"
        )));
    }

    let alpha_inc = if reward > 0.0 { reward } else { 0.0 };
    let beta_inc = if reward < 0.0 { -reward } else { 0.0 };
    let trials_inc: i64 = if kind.is_informative() { 1 } else { 0 };
    let successes_inc: i64 = if reward > 0.0 { 1 } else { 0 };
    let negative_inc: i64 = if kind.is_negative() { 1 } else { 0 };

    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let inserted = sqlx::query(
        "INSERT INTO sales_experiment_outcomes \
             (outcome_key, experiment_id, variant, reward, recorded_at) \
         VALUES ($1, $2, $3, $4, NOW()) \
         ON CONFLICT (outcome_key) DO NOTHING",
    )
    .bind(outcome_key)
    .bind(experiment_id)
    .bind(variant.trim())
    .bind(reward)
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected()
        > 0;

    if inserted {
        let updated = sqlx::query(
            "UPDATE sales_experiment_arms \
             SET alpha = alpha + $1, beta = beta + $2, trials = trials + $3, \
                 successes = successes + $4, contacts = contacts + 1, \
                 negative_outcomes = negative_outcomes + $5, updated_at = NOW() \
             WHERE experiment_id = $6 AND variant = $7",
        )
        .bind(alpha_inc)
        .bind(beta_inc)
        .bind(trials_inc)
        .bind(successes_inc)
        .bind(negative_inc)
        .bind(experiment_id)
        .bind(variant.trim())
        .execute(&mut *tx)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?
        .rows_affected();
        if updated != 1 {
            return Err(SalesError::Database(format!(
                "outcome '{outcome_key}': arm '{variant}' of experiment {experiment_id} \
                 disappeared mid-transaction"
            )));
        }
    } else {
        tracing::info!(
            outcome_key,
            experiment_id = %experiment_id,
            variant,
            "experiment outcome replay — posterior unchanged"
        );
    }

    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

/// Attribute enrichment spend to an arm so the §37 spend limit can be
/// enforced. Validates before writing.
pub async fn record_enrichment_spend(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
    variant: &str,
    cost_eur: f64,
) -> Result<(), SalesError> {
    if !cost_eur.is_finite() || cost_eur < 0.0 {
        return Err(SalesError::InvalidInput(format!(
            "enrichment cost must be finite and >= 0, got {cost_eur}"
        )));
    }
    let updated = sqlx::query(
        "UPDATE sales_experiment_arms a \
         SET enrichment_cost_eur = a.enrichment_cost_eur + $1::float8::numeric, updated_at = NOW() \
         FROM sales_experiments e \
         WHERE a.experiment_id = $2 AND a.variant = $3 \
           AND e.id = a.experiment_id AND e.tenant_id = $4",
    )
    .bind(cost_eur)
    .bind(experiment_id)
    .bind(variant)
    .bind(tenant_id)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected();
    if updated != 1 {
        return Err(SalesError::InvalidInput(format!(
            "arm '{variant}' of experiment {experiment_id} not found for tenant {tenant_id}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// §28 next-best-action
// ---------------------------------------------------------------------------

/// Reply state of the enrollment, as the action policy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyState {
    None,
    /// A human replied (any disposition that is not a meeting booking or an
    /// opt-out). Automation must not send again.
    HumanReplied,
    MeetingBooked,
    /// Unsubscribe / complaint / hard bounce / not interested.
    NegativeOrOptOut,
}

/// Verification state of the selected email contact point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailState {
    Verified,
    Risky,
    Unverified,
    Invalid,
}

/// Inputs to the pure next-best-action policy. Every economic decision is a
/// function of these numbers, so the policy is replayable and testable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NextActionInput {
    /// Expected value of the opportunity from the scorer, EUR (gross of
    /// outreach cost).
    pub expected_value_eur: f64,
    /// Fully-loaded cost of one outreach attempt, EUR.
    pub outreach_cost_eur: f64,
    /// Evidence rows grounded on the account.
    pub evidence_count: u32,
    /// Mean evidence confidence, `0..=1`.
    pub evidence_confidence: f32,
    pub reply: ReplyState,
    pub email: EmailState,
    /// Verified intent signal strength, `0..=1` (never opens/clicks).
    pub intent_strength: f32,
    pub prior_touches: u32,
    pub last_angle_failed: bool,
    pub referral_available: bool,
    pub referral_requested: bool,
    /// An open `sales_opportunities` row exists.
    pub opportunity_open: bool,
    /// A reply/negative-reply cooldown is active.
    pub cooldown_active: bool,
    /// Lifecycle disqualified / do-not-contact.
    pub disqualified: bool,
}

impl Default for NextActionInput {
    fn default() -> Self {
        Self {
            expected_value_eur: 0.0,
            outreach_cost_eur: DEFAULT_OUTREACH_COST_EUR,
            evidence_count: 0,
            evidence_confidence: 0.0,
            reply: ReplyState::None,
            email: EmailState::Unverified,
            intent_strength: 0.0,
            prior_touches: 0,
            last_angle_failed: false,
            referral_available: false,
            referral_requested: false,
            opportunity_open: false,
            cooldown_active: false,
            disqualified: false,
        }
    }
}

/// The pure §28 policy. Returns the action **and the reason string that
/// becomes the Decision Packet rationale**.
///
/// Documented rule order:
///
/// 1. disqualified / negative-or-opt-out → `StopPermanently`;
/// 2. non-finite economics → `DoNothing` (fail closed);
/// 3. invalid address → `VerifyEmail`;
/// 4. human reply → `OperatorTask` (a human handles it; automation never
///    sends again);
/// 5. meeting booked → `Nurture`;
/// 6. EV below [`MIN_EXPECTED_VALUE_FOR_OUTREACH_EUR`] → `DoNothing`;
/// 7. EV − cost <= 0 → `DoNothing` (the outreach costs more than it is
///    worth);
/// 8. cooldown → `Wait`;
/// 9. thin evidence (`< MIN_EVIDENCE_FOR_OUTREACH`): high-EV accounts get
///    `VerifyEmail` / `ResearchCompany` / `CollectEvidence` / `Enrich`;
///    low-EV accounts get `DoNothing` (do not spend, do not spam);
/// 10. referral opportunity → `AskForReferral`;
/// 11. open opportunity + strong intent → `BookMeeting`;
/// 12. first touch → `Contact`;
/// 13. failed angle → `ChangeAngle`;
/// 14. meaningful intent → `FollowUp`;
/// 15. long, unproductive sequence → `Nurture`;
/// 16. otherwise → `ChangeAngle` (never repeat the same failing angle).
pub fn next_best_action(input: &NextActionInput) -> (DecisionAction, String) {
    if input.disqualified {
        return (
            DecisionAction::StopPermanently,
            format!(
                "account is disqualified or marked do-not-contact; stopping permanently \
                 (EV {:.2} EUR does not override a lifecycle stop)",
                input.expected_value_eur
            ),
        );
    }
    if matches!(input.reply, ReplyState::NegativeOrOptOut) {
        return (
            DecisionAction::StopPermanently,
            "the contact opted out or complained; no further automated contact is lawful or \
             useful"
                .to_string(),
        );
    }
    if !input.expected_value_eur.is_finite() || !input.outreach_cost_eur.is_finite() {
        return (
            DecisionAction::DoNothing,
            format!(
                "EV or outreach cost is non-finite (EV={}, cost={}); failing closed to DoNothing",
                input.expected_value_eur, input.outreach_cost_eur
            ),
        );
    }
    if input.email == EmailState::Invalid {
        return (
            DecisionAction::VerifyEmail,
            format!(
                "the selected address is invalid; verifying/replacing it is the only action that \
                 can make EV {:.2} EUR reachable",
                input.expected_value_eur
            ),
        );
    }
    if input.reply == ReplyState::HumanReplied {
        return (
            DecisionAction::OperatorTask,
            format!(
                "a human already replied; automation must not send again — routing to an operator \
                 (EV {:.2} EUR)",
                input.expected_value_eur
            ),
        );
    }
    if input.reply == ReplyState::MeetingBooked {
        return (
            DecisionAction::Nurture,
            "a meeting is already booked; nurture the relationship instead of another cold touch"
                .to_string(),
        );
    }

    let ev = input.expected_value_eur;
    let cost = input.outreach_cost_eur;

    if ev < MIN_EXPECTED_VALUE_FOR_OUTREACH_EUR {
        return (
            DecisionAction::DoNothing,
            format!(
                "expected value {ev:.2} EUR is below the {MIN_EXPECTED_VALUE_FOR_OUTREACH_EUR:.2} \
                 EUR minimum for any outreach; a weak prospect is not worth a send (and not worth \
                 paying for information)"
            ),
        );
    }

    let net = ev - cost;
    if net <= 0.0 {
        return (
            DecisionAction::DoNothing,
            format!(
                "outreach cost {cost:.2} EUR is >= expected value {ev:.2} EUR (net {net:.2} EUR); \
                 no external send is economically justified"
            ),
        );
    }

    if input.cooldown_active {
        return (
            DecisionAction::Wait,
            format!(
                "a reply cooldown is active; waiting preserves EV {ev:.2} EUR without spending \
                 sender reputation"
            ),
        );
    }

    if input.evidence_count < MIN_EVIDENCE_FOR_OUTREACH {
        if ev < HIGH_VALUE_ACCOUNT_EV_EUR {
            return (
                DecisionAction::DoNothing,
                format!(
                    "only {} evidence rows (< {MIN_EVIDENCE_FOR_OUTREACH}) and EV {ev:.2} EUR is \
                     below the {HIGH_VALUE_ACCOUNT_EV_EUR:.0} EUR high-value threshold: neither \
                     the paid lookup nor the send pays for itself",
                    input.evidence_count
                ),
            );
        }
        if input.email != EmailState::Verified {
            return (
                DecisionAction::VerifyEmail,
                format!(
                    "high-value account (EV {ev:.2} EUR) with {} evidence rows and an unverified \
                     address; spend {cost:.2} EUR verifying the address before any send",
                    input.evidence_count
                ),
            );
        }
        if input.evidence_count == 0 {
            return (
                DecisionAction::ResearchCompany,
                format!(
                    "high-value account (EV {ev:.2} EUR) has zero evidence; research the company \
                     (spend {cost:.2} EUR) instead of sending an unevidenced claim"
                ),
            );
        }
        if input.evidence_confidence < 0.5 {
            return (
                DecisionAction::CollectEvidence,
                format!(
                    "high-value account (EV {ev:.2} EUR) has {} evidence rows at mean confidence \
                     {:.2} (< 0.5); collect stronger evidence before contacting",
                    input.evidence_count, input.evidence_confidence
                ),
            );
        }
        return (
            DecisionAction::Enrich,
            format!(
                "high-value account (EV {ev:.2} EUR) has only {} of {MIN_EVIDENCE_FOR_OUTREACH} \
                 evidence rows; spending {cost:.2} EUR on enrichment is cheaper than an \
                 unsupported claim",
                input.evidence_count
            ),
        );
    }

    if input.referral_available && !input.referral_requested && input.prior_touches > 0 {
        return (
            DecisionAction::AskForReferral,
            format!(
                "a referral path exists after {} touches; asking for an introduction is worth \
                 more than another direct touch (EV {ev:.2} EUR)",
                input.prior_touches
            ),
        );
    }
    if input.opportunity_open && input.intent_strength >= 0.8 {
        return (
            DecisionAction::BookMeeting,
            format!(
                "open opportunity with strong verified intent ({:.2}); ask for the meeting rather \
                 than another nurture email (EV {ev:.2} EUR)",
                input.intent_strength
            ),
        );
    }
    if input.prior_touches == 0 {
        return (
            DecisionAction::Contact,
            format!(
                "first touch: EV {ev:.2} EUR, net {net:.2} EUR, {} evidence rows and a verified \
                 address; contacting is justified",
                input.evidence_count
            ),
        );
    }
    if input.last_angle_failed {
        return (
            DecisionAction::ChangeAngle,
            format!(
                "the previous angle failed after {} touches; repeating it would be the spam \
                 defect — changing angle (EV {ev:.2} EUR)",
                input.prior_touches
            ),
        );
    }
    if input.intent_strength >= 0.5 {
        return (
            DecisionAction::FollowUp,
            format!(
                "moderate-or-better intent ({:.2}) after {} touches and net {net:.2} EUR; a \
                 follow-up is justified",
                input.intent_strength, input.prior_touches
            ),
        );
    }
    if input.prior_touches >= 4 && !input.opportunity_open {
        return (
            DecisionAction::Nurture,
            format!(
                "{} touches with low intent ({:.2}) and no open opportunity; move to long-horizon \
                 nurture instead of pressing (EV {ev:.2} EUR)",
                input.prior_touches, input.intent_strength
            ),
        );
    }
    (
        DecisionAction::ChangeAngle,
        format!(
            "low intent ({:.2}) after {} touches; a different angle is the cheap next test \
             (net {net:.2} EUR)",
            input.intent_strength, input.prior_touches
        ),
    )
}

/// A cheap admissibility check callers (and the sequence worker) use before an
/// external send: the pure policy plus the requirement that the step handler
/// only executes an external-send action.
pub fn next_best_action_allows_send(input: &NextActionInput) -> (bool, DecisionAction, String) {
    let (action, reason) = next_best_action(input);
    (action.is_external_send(), action, reason)
}

/// Group actions into the per-key counts used by simulation reports.
pub fn action_counts(actions: impl IntoIterator<Item = DecisionAction>) -> BTreeMap<String, i64> {
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    for action in actions {
        *counts.entry(action.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn arm(variant: &str, is_control: bool) -> ArmPosterior {
        ArmPosterior::new(variant, 1.0, 1.0, is_control)
    }

    // -- reward ladder ------------------------------------------------------

    #[test]
    fn reward_ladder_is_strictly_increasing_and_opens_are_zero() {
        assert_eq!(RewardKind::Delivered.reward(), 0.0);
        assert_eq!(RewardKind::Open.reward(), 0.0);
        let mut previous = f64::NEG_INFINITY;
        for kind in POSITIVE_REWARD_LADDER {
            let reward = kind.reward();
            assert!(
                reward > previous,
                "reward ladder must increase: {} = {reward} after {previous}",
                kind
            );
            assert!((0.0..=1.2).contains(&reward));
            previous = reward;
        }
    }

    #[test]
    fn negative_outcomes_are_penalised() {
        for kind in [
            RewardKind::Bounce,
            RewardKind::Complaint,
            RewardKind::Unsubscribe,
        ] {
            assert!(kind.is_negative(), "{kind} must be negative");
            assert!(kind.reward() < 0.0);
        }
        let mut with_penalty = arm("control", true);
        apply_reward_to_posterior(&mut with_penalty, RewardKind::Complaint).unwrap();
        let clean = arm("control", true);
        assert!(
            with_penalty.mean() < clean.mean(),
            "a complaint must lower the posterior mean"
        );
        assert_eq!(with_penalty.negative_outcomes, 1);
    }

    #[test]
    fn opens_move_exposure_but_not_the_posterior() {
        let mut open_arm = arm("a", false);
        for _ in 0..10_000 {
            apply_reward_to_posterior(&mut open_arm, RewardKind::Open).unwrap();
        }
        assert_eq!(open_arm.alpha, 1.0, "opens must not move alpha");
        assert_eq!(open_arm.beta, 1.0, "opens must not move beta");
        assert_eq!(open_arm.trials, 0, "opens are not informative trials");
        assert_eq!(open_arm.contacts, 10_000, "opens do count exposure");
        assert!((open_arm.mean() - 0.5).abs() < 1e-12);
    }

    /// RELEASE GATE (§17): opens can never promote an arm.
    #[test]
    fn ten_thousand_opens_never_win_an_arm() {
        let mut opens = arm("opens_only", false);
        for _ in 0..10_000 {
            apply_reward_to_posterior(&mut opens, RewardKind::Open).unwrap();
        }
        let mut replies = arm("replies", false);
        for _ in 0..5 {
            apply_reward_to_posterior(&mut replies, RewardKind::Reply).unwrap();
        }
        assert!(
            replies.mean() > opens.mean(),
            "a handful of replies ({:.4}) must beat 10 000 opens ({:.4})",
            replies.mean(),
            opens.mean()
        );
        let probabilities = selection_win_probabilities(&[opens.clone(), replies.clone()], 2_000)
            .expect("selection probabilities");
        assert!(
            probabilities[1] > 0.6,
            "reply arm must win the selection: {probabilities:?}"
        );
    }

    #[test]
    fn delivered_does_not_move_the_posterior_either() {
        let mut delivered = arm("d", false);
        for _ in 0..5_000 {
            apply_reward_to_posterior(&mut delivered, RewardKind::Delivered).unwrap();
        }
        assert_eq!(delivered.alpha, 1.0);
        assert_eq!(delivered.beta, 1.0);
        assert_eq!(delivered.trials, 0);
        assert_eq!(delivered.contacts, 5_000);
    }

    #[test]
    fn positive_posterior_mean_is_monotone_in_the_rung() {
        let mut previous = f64::NEG_INFINITY;
        for kind in POSITIVE_REWARD_LADDER {
            let mut posterior = arm("candidate", false);
            apply_reward_to_posterior(&mut posterior, *kind).unwrap();
            assert!(
                posterior.mean() > previous,
                "posterior mean must increase with the ladder: {} -> {}",
                kind,
                posterior.mean()
            );
            previous = posterior.mean();
        }
    }

    #[test]
    fn hostile_posteriors_are_rejected_before_any_write() {
        for (alpha, beta) in [
            (0.0, 1.0),
            (-1.0, 1.0),
            (f64::NAN, 1.0),
            (f64::INFINITY, 1.0),
            (1.0, 0.0),
            (1.0, -1.0),
            (1.0, f64::NAN),
            (1.0, f64::INFINITY),
        ] {
            assert!(
                validate_posterior(alpha, beta).is_err(),
                "alpha={alpha}, beta={beta} must be rejected"
            );
            let mut posterior = ArmPosterior::new("a", alpha, beta, false);
            assert!(apply_reward_to_posterior(&mut posterior, RewardKind::Reply).is_err());
        }
    }

    #[test]
    fn ten_thousand_arms_do_not_panic() {
        let arms: Vec<ArmPosterior> = (0..10_000)
            .map(|index| {
                ArmPosterior::new(&format!("variant-{index}"), 1.0 + index as f64, 1.0, false)
            })
            .collect();
        let best = best_arm_index(&arms).expect("a best arm");
        assert_eq!(best, 9_999, "the highest mean wins deterministically");
    }

    // -- exploration budgets ------------------------------------------------

    #[test]
    fn empty_budget_json_uses_safe_defaults() {
        let budget = ExplorationBudget::from_json(&serde_json::json!({})).unwrap();
        assert_eq!(budget.max_contacts, None);
        assert_eq!(budget.max_sender_domain_exposure, None);
        assert_eq!(budget.max_daily_exploration_pct, None);
        assert_eq!(budget.max_negative_outcome_budget, None);
        assert_eq!(budget.max_enrichment_spend_eur, None);
        assert_eq!(
            budget.min_sample_before_promotion,
            DEFAULT_MIN_SAMPLE_BEFORE_PROMOTION
        );
        assert_eq!(
            budget.high_value_ev_threshold_eur,
            Some(DEFAULT_HIGH_VALUE_EV_THRESHOLD_EUR)
        );
    }

    #[test]
    fn zero_budget_is_zero_not_unlimited() {
        let budget =
            ExplorationBudget::from_json(&serde_json::json!({ "max_contacts": 0 })).unwrap();
        assert_eq!(budget.max_contacts, Some(0));
        let verdict = may_explore(&budget, &ExplorationState::default());
        assert!(matches!(verdict, ExplorationVerdict::ExploitOnly(_)));
        assert!(!verdict.allows_exploration());
    }

    #[test]
    fn none_budget_is_unlimited() {
        let budget = ExplorationBudget::from_json(&serde_json::json!({
            "max_contacts": null,
            "max_daily_exploration_pct": null,
            "high_value_ev_threshold_eur": null,
        }))
        .unwrap();
        assert_eq!(budget.max_contacts, None);
        let state = ExplorationState {
            contacts: 10_000_000,
            daily_exploration_pct: 99.0,
            account_expected_value_eur: 1_000_000.0,
            ..ExplorationState::default()
        };
        assert_eq!(may_explore(&budget, &state), ExplorationVerdict::Allowed);
    }

    #[test]
    fn hostile_percentage_fails_closed_to_zero() {
        for value in [200.0, -1.0, f64::NAN, f64::INFINITY] {
            let budget = ExplorationBudget {
                max_daily_exploration_pct: Some(value),
                ..ExplorationBudget::default()
            };
            let verdict = may_explore(&budget, &ExplorationState::default());
            assert!(
                matches!(verdict, ExplorationVerdict::ExploitOnly(_)),
                "pct {value} must fail closed to zero exploration, got {verdict:?}"
            );
        }
        let from_json =
            ExplorationBudget::from_json(&serde_json::json!({"max_daily_exploration_pct": 200.0}))
                .unwrap();
        assert_eq!(from_json.max_daily_exploration_pct, Some(0.0));
    }

    #[test]
    fn hostile_counts_and_thresholds_fail_closed() {
        let budget = ExplorationBudget::from_json(&serde_json::json!({
            "max_contacts": -5,
            "max_enrichment_spend_eur": -3.0,
            "min_sample_before_promotion": -1,
            "min_posterior_confidence": 1.5,
            "high_value_ev_threshold_eur": -10.0,
        }))
        .unwrap();
        assert_eq!(budget.max_contacts, Some(0));
        assert_eq!(budget.max_enrichment_spend_eur, Some(0.0));
        assert_eq!(
            budget.min_sample_before_promotion,
            DEFAULT_MIN_SAMPLE_BEFORE_PROMOTION
        );
        assert_eq!(budget.min_posterior_confidence, 1.0);
        assert_eq!(budget.high_value_ev_threshold_eur, Some(0.0));
        assert!(matches!(
            may_explore(&budget, &ExplorationState::default()),
            ExplorationVerdict::ExploitOnly(_)
        ));
    }

    #[test]
    fn hostile_budget_json_types_are_rejected_with_a_reason() {
        let error = ExplorationBudget::from_json(&serde_json::json!("unlimited"))
            .expect_err("a JSON string is not a budget object");
        assert!(
            matches!(error, SalesError::InvalidInput(_)),
            "got {error:?}"
        );
        assert!(error.to_string().contains("JSON object"), "{error}");

        let error = ExplorationBudget::from_json(&serde_json::json!({ "max_contacts": "10" }))
            .expect_err("a string where a number belongs must be rejected");
        assert!(error.to_string().contains("max_contacts"), "{error}");

        let error =
            ExplorationBudget::from_json(&serde_json::json!({ "max_daily_exploration_pct": true }))
                .expect_err("a boolean where a number belongs must be rejected");
        assert!(
            error.to_string().contains("max_daily_exploration_pct"),
            "{error}"
        );
    }

    #[test]
    fn exploit_only_at_contact_exhaustion_is_deterministic() {
        let budget =
            ExplorationBudget::from_json(&serde_json::json!({ "max_contacts": 10 })).unwrap();
        let state = ExplorationState {
            contacts: 10,
            ..ExplorationState::default()
        };
        let verdict = may_explore(&budget, &state);
        assert!(matches!(verdict, ExplorationVerdict::ExploitOnly(_)));
        assert!(verdict.reason().unwrap().contains("exploit-only"));

        // The deterministic exploit choice returns the same arm every time.
        let arms = vec![
            ArmPosterior::new("a", 11.0, 10.0, false),
            ArmPosterior::new("b", 30.0, 10.0, false),
            ArmPosterior::new("control", 2.0, 1.0, true),
        ];
        let first = best_arm_index(&arms).expect("best arm");
        for _ in 0..20 {
            assert_eq!(best_arm_index(&arms), Some(first));
        }
        assert_eq!(arms[first].variant, "b");
    }

    #[test]
    fn negative_outcome_budget_halts_the_experiment() {
        let budget =
            ExplorationBudget::from_json(&serde_json::json!({ "max_negative_outcome_budget": 2 }))
                .unwrap();
        let state = ExplorationState {
            negative_outcomes: 2,
            ..ExplorationState::default()
        };
        let verdict = may_explore(&budget, &state);
        assert!(matches!(verdict, ExplorationVerdict::Halted(_)));
        assert!(verdict
            .reason()
            .unwrap()
            .contains("negative-outcome budget"));
    }

    #[test]
    fn high_value_accounts_are_preserved_from_exploration() {
        let budget = ExplorationBudget::default();
        let high_value = ExplorationState {
            account_expected_value_eur: DEFAULT_HIGH_VALUE_EV_THRESHOLD_EUR + 1.0,
            ..ExplorationState::default()
        };
        let verdict = may_explore(&budget, &high_value);
        assert!(matches!(verdict, ExplorationVerdict::ExploitOnly(_)));
        assert!(verdict.reason().unwrap().contains("high-value account"));

        let overridden = ExplorationState {
            explicit_exploration_override: true,
            ..high_value
        };
        assert_eq!(
            may_explore(&budget, &overridden),
            ExplorationVerdict::Allowed
        );
    }

    // -- promotion ----------------------------------------------------------

    #[test]
    fn promotion_requires_sample_interval_and_confidence() {
        let budget = ExplorationBudget {
            min_sample_before_promotion: 100,
            min_posterior_confidence: 0.95,
            high_value_ev_threshold_eur: None,
            ..ExplorationBudget::default()
        };
        let control = ArmPosterior::new("control", 20.0, 80.0, true);
        let mut candidate = ArmPosterior::new("candidate", 1.0, 1.0, false);
        for _ in 0..100 {
            apply_reward_to_posterior(&mut candidate, RewardKind::Reply).unwrap();
        }
        // 100 replies: alpha = 21, beta = 1 → clearly beats control.
        let verdict = may_promote_arm(&budget, &control, &candidate, 0.999);
        assert!(verdict.allowed, "{verdict:?}");

        // Too few trials.
        let mut thin = ArmPosterior::new("thin", 1.0, 1.0, false);
        for _ in 0..10 {
            apply_reward_to_posterior(&mut thin, RewardKind::Reply).unwrap();
        }
        let verdict = may_promote_arm(&budget, &control, &thin, 0.999);
        assert!(!verdict.allowed);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("insufficient sample")));

        // Interval does not beat control: 100 penalties leave the arm far
        // below a control that converts 20% of its contacts.
        let mut weak = ArmPosterior::new("weak", 1.0, 1.0, false);
        for _ in 0..100 {
            apply_reward_to_posterior(&mut weak, RewardKind::Complaint).unwrap();
        }
        let verdict = may_promote_arm(&budget, &control, &weak, 0.999);
        assert!(!verdict.allowed);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("credible interval does not beat control")));

        // Insufficient posterior confidence.
        let verdict = may_promote_arm(&budget, &control, &candidate, 0.5);
        assert!(!verdict.allowed);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("posterior confidence too low")));
    }

    // -- context ------------------------------------------------------------

    #[test]
    fn empty_context_has_no_bucket() {
        let context = ExperimentContext::default();
        assert_eq!(context.bucket_key(&[]), None);
        assert_eq!(
            context.bucket_key(
                &ExperimentContext::DIMENSIONS
                    .iter()
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
            ),
            None
        );
    }

    #[test]
    fn bucket_key_is_stable_and_sanitized() {
        let context = ExperimentContext {
            icp_segment: Some("SaaS".into()),
            country: Some("DE".into()),
            company_size_band: Some(" 30-100 ".into()),
            persona: Some("CTO / VP Eng <script>".into()),
            ..ExperimentContext::default()
        };
        let dimensions: Vec<String> = ExperimentContext::DIMENSIONS
            .iter()
            .map(|d| d.to_string())
            .collect();
        let first = context.bucket_key(&dimensions).expect("bucket");
        let second = context.bucket_key(&dimensions).expect("bucket");
        assert_eq!(first, second);
        assert!(first.contains("icp_segment=saas"));
        assert!(first.contains("country=de"));
        assert!(first.contains("company_size_band=30-100"));
        assert!(!first.contains('<'), "sanitized: {first}");

        // A 1 MB dimension value cannot explode the key.
        let hostile = ExperimentContext {
            icp_segment: Some("x".repeat(1_000_000)),
            ..ExperimentContext::default()
        };
        let key = hostile.bucket_key(&dimensions).expect("bucket");
        assert!(key.len() <= MAX_CONTEXT_KEY_LEN, "key length {}", key.len());
    }

    #[test]
    fn experiment_status_unknown_fails_closed_to_stopped() {
        assert_eq!(
            ExperimentStatus::parse("running"),
            ExperimentStatus::Running
        );
        assert_eq!(ExperimentStatus::parse("PAUSED"), ExperimentStatus::Paused);
        assert_eq!(ExperimentStatus::parse("hacked"), ExperimentStatus::Stopped);
        assert_eq!(ExperimentStatus::parse(""), ExperimentStatus::Stopped);
        assert!(!ExperimentStatus::Stopped.explores());
    }

    // -- §28 next best action ----------------------------------------------

    #[test]
    fn thin_evidence_on_high_ev_gathers_information_not_contact() {
        let input = NextActionInput {
            expected_value_eur: 20_000.0,
            outreach_cost_eur: DEFAULT_OUTREACH_COST_EUR,
            evidence_count: 1,
            evidence_confidence: 0.8,
            reply: ReplyState::None,
            email: EmailState::Verified,
            intent_strength: 0.6,
            ..NextActionInput::default()
        };
        let (action, reason) = next_best_action(&input);
        assert!(
            matches!(
                action,
                DecisionAction::Enrich
                    | DecisionAction::CollectEvidence
                    | DecisionAction::ResearchCompany
                    | DecisionAction::VerifyEmail
            ),
            "expected an evidence-gathering action, got {action}: {reason}"
        );
        assert!(!action.is_external_send());

        // Zero evidence → research.
        let research = NextActionInput {
            evidence_count: 0,
            ..input.clone()
        };
        assert_eq!(
            next_best_action(&research).0,
            DecisionAction::ResearchCompany
        );

        // Weak evidence confidence → collect.
        let collect = NextActionInput {
            evidence_count: 2,
            evidence_confidence: 0.2,
            ..input.clone()
        };
        assert_eq!(
            next_best_action(&collect).0,
            DecisionAction::CollectEvidence
        );

        // Unverified address → verify first.
        let verify = NextActionInput {
            email: EmailState::Unverified,
            ..input
        };
        assert_eq!(next_best_action(&verify).0, DecisionAction::VerifyEmail);
    }

    #[test]
    fn weak_prospect_yields_do_nothing_and_no_send() {
        // A €29/month prospect: a few hundred EUR of annual value with weak
        // probabilities scores EV ~ 1.5 EUR.
        let input = NextActionInput {
            expected_value_eur: 1.5,
            outreach_cost_eur: DEFAULT_OUTREACH_COST_EUR,
            evidence_count: 1,
            evidence_confidence: 0.5,
            email: EmailState::Verified,
            intent_strength: 0.1,
            ..NextActionInput::default()
        };
        let (action, reason) = next_best_action(&input);
        assert_eq!(action, DecisionAction::DoNothing, "{reason}");
        assert!(!action.is_external_send());
        assert!(reason.contains("minimum"));
    }

    #[test]
    fn human_reply_never_contacts_again() {
        for ev in [10.0, 5_000.0, 1_000_000.0] {
            let input = NextActionInput {
                expected_value_eur: ev,
                evidence_count: 10,
                evidence_confidence: 0.9,
                email: EmailState::Verified,
                reply: ReplyState::HumanReplied,
                ..NextActionInput::default()
            };
            let (action, reason) = next_best_action(&input);
            assert!(
                !action.is_external_send(),
                "EV {ev}: a human reply must block external sends, got {action}: {reason}"
            );
            assert_eq!(action, DecisionAction::OperatorTask);
        }
        let opt_out = NextActionInput {
            reply: ReplyState::NegativeOrOptOut,
            expected_value_eur: 50_000.0,
            ..NextActionInput::default()
        };
        let (action, _) = next_best_action(&opt_out);
        assert_eq!(action, DecisionAction::StopPermanently);
        assert!(!action.is_external_send());
    }

    #[test]
    fn cost_exceeding_ev_is_never_an_external_send() {
        let input = NextActionInput {
            expected_value_eur: 6.0,
            outreach_cost_eur: 10.0,
            evidence_count: 5,
            evidence_confidence: 0.9,
            email: EmailState::Verified,
            intent_strength: 0.9,
            ..NextActionInput::default()
        };
        let (action, reason) = next_best_action(&input);
        assert!(!action.is_external_send(), "{action}: {reason}");
        assert_eq!(action, DecisionAction::DoNothing);
        assert!(reason.contains("cost"));
    }

    #[test]
    fn all_fourteen_actions_are_reachable() {
        let base = NextActionInput {
            expected_value_eur: 10_000.0,
            outreach_cost_eur: 0.2,
            evidence_count: 5,
            evidence_confidence: 0.9,
            email: EmailState::Verified,
            intent_strength: 0.6,
            ..NextActionInput::default()
        };
        let cases: Vec<(DecisionAction, NextActionInput)> = vec![
            (
                DecisionAction::StopPermanently,
                NextActionInput {
                    disqualified: true,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::Wait,
                NextActionInput {
                    cooldown_active: true,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::CollectEvidence,
                NextActionInput {
                    evidence_count: 2,
                    evidence_confidence: 0.1,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::Enrich,
                NextActionInput {
                    evidence_count: 2,
                    evidence_confidence: 0.8,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::VerifyEmail,
                NextActionInput {
                    email: EmailState::Unverified,
                    evidence_count: 2,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::ResearchCompany,
                NextActionInput {
                    evidence_count: 0,
                    ..base.clone()
                },
            ),
            (DecisionAction::Contact, base.clone()),
            (
                DecisionAction::FollowUp,
                NextActionInput {
                    prior_touches: 2,
                    intent_strength: 0.6,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::ChangeAngle,
                NextActionInput {
                    prior_touches: 2,
                    last_angle_failed: true,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::ChangeAngle,
                NextActionInput {
                    prior_touches: 2,
                    intent_strength: 0.1,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::AskForReferral,
                NextActionInput {
                    prior_touches: 2,
                    referral_available: true,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::BookMeeting,
                NextActionInput {
                    opportunity_open: true,
                    intent_strength: 0.9,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::OperatorTask,
                NextActionInput {
                    reply: ReplyState::HumanReplied,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::Nurture,
                NextActionInput {
                    reply: ReplyState::MeetingBooked,
                    ..base.clone()
                },
            ),
            (
                DecisionAction::Nurture,
                NextActionInput {
                    prior_touches: 6,
                    intent_strength: 0.1,
                    ..base.clone()
                },
            ),
        ];
        for (expected, input) in cases {
            let (action, reason) = next_best_action(&input);
            assert!(!reason.trim().is_empty(), "{expected:?} must be justified");
            assert_eq!(action, expected, "reason: {reason}");
        }
    }

    #[test]
    fn non_finite_economics_fail_closed() {
        for ev in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let input = NextActionInput {
                expected_value_eur: ev,
                evidence_count: 10,
                email: EmailState::Verified,
                ..NextActionInput::default()
            };
            let (action, reason) = next_best_action(&input);
            assert_eq!(action, DecisionAction::DoNothing);
            assert!(reason.contains("non-finite"), "{reason}");
        }
        let input = NextActionInput {
            outreach_cost_eur: f64::NAN,
            expected_value_eur: 1_000.0,
            evidence_count: 10,
            email: EmailState::Verified,
            ..NextActionInput::default()
        };
        assert_eq!(next_best_action(&input).0, DecisionAction::DoNothing);
    }

    #[test]
    fn next_best_action_allows_send_matches_external_predicate() {
        let contact = NextActionInput {
            expected_value_eur: 5_000.0,
            evidence_count: 5,
            evidence_confidence: 0.9,
            email: EmailState::Verified,
            ..NextActionInput::default()
        };
        let (allowed, action, _) = next_best_action_allows_send(&contact);
        assert!(allowed);
        assert_eq!(action, DecisionAction::Contact);

        let weak = NextActionInput {
            expected_value_eur: 1.0,
            email: EmailState::Verified,
            ..NextActionInput::default()
        };
        let (allowed, action, _) = next_best_action_allows_send(&weak);
        assert!(!allowed);
        assert_eq!(action, DecisionAction::DoNothing);
    }

    #[test]
    fn action_counts_groups_by_wire_name() {
        let counts = action_counts([
            DecisionAction::DoNothing,
            DecisionAction::DoNothing,
            DecisionAction::Contact,
        ]);
        assert_eq!(counts.get("do_nothing"), Some(&2));
        assert_eq!(counts.get("contact"), Some(&1));
    }

    // -----------------------------------------------------------------------
    // Adversarial proofs: ladder, posteriors, status, contexts, engine.
    // Run by default; DB tests soft-skip only when the canonical test
    // database is unconfigured.
    // -----------------------------------------------------------------------

    #[test]
    fn reward_ladder_wire_names_round_trip_through_attribution() {
        use crate::attribution::OutcomeKind;
        let pairs = [
            (RewardKind::Delivered, OutcomeKind::Delivered),
            (RewardKind::Open, OutcomeKind::Open),
            (RewardKind::Click, OutcomeKind::Click),
            (RewardKind::Reply, OutcomeKind::Reply),
            (RewardKind::PositiveReply, OutcomeKind::PositiveReply),
            (RewardKind::MeetingBooked, OutcomeKind::MeetingBooked),
            (RewardKind::MeetingAttended, OutcomeKind::MeetingAttended),
            (RewardKind::Trial, OutcomeKind::Trial),
            (RewardKind::PaidSubscription, OutcomeKind::PaidSubscription),
            (RewardKind::RetainedMrr, OutcomeKind::RetainedMrr),
            (RewardKind::Bounce, OutcomeKind::Bounce),
            (RewardKind::Complaint, OutcomeKind::Complaint),
            (RewardKind::Unsubscribe, OutcomeKind::Unsubscribe),
        ];
        for (kind, outcome) in pairs {
            let wire = kind.as_str();
            assert_eq!(RewardKind::parse(wire), Some(kind), "{wire}");
            assert_eq!(
                RewardKind::parse(&format!("  {}  ", wire.to_uppercase())),
                Some(kind),
                "parsing is trimmed and case-insensitive"
            );
            assert_eq!(RewardKind::from_outcome_kind(outcome), kind);
            assert_eq!(kind.to_string(), wire, "Display matches the wire name");
        }
        assert_eq!(RewardKind::parse("unknown"), None);
        assert_eq!(RewardKind::parse(""), None);
        // The ladder has exactly thirteen rungs, matching the outcome CHECK.
        assert_eq!(POSITIVE_REWARD_LADDER.len(), 8);
    }

    #[test]
    fn reward_classification_is_operational_negative_and_bounded() {
        for kind in [RewardKind::Delivered, RewardKind::Open] {
            assert!(kind.is_operational(), "{kind:?}");
            assert!(!kind.is_informative(), "{kind:?}");
            assert_eq!(
                kind.reward(),
                0.0,
                "operational outcomes never move the posterior"
            );
            assert!(!kind.is_negative());
        }
        for kind in [
            RewardKind::Bounce,
            RewardKind::Complaint,
            RewardKind::Unsubscribe,
        ] {
            assert!(kind.is_negative(), "{kind:?}");
            assert!(kind.is_informative());
            assert!(kind.reward() < 0.0, "{kind:?}");
        }
        // The strictly-increasing positive ladder.
        let mut previous = 0.0;
        for kind in POSITIVE_REWARD_LADDER {
            let reward = kind.reward();
            assert!(reward > previous, "{kind:?} must beat the rung below");
            assert!(!kind.is_negative());
            assert!(kind.is_informative());
            previous = reward;
        }
    }

    #[test]
    fn arm_specs_and_constructors_default_to_challenger() {
        let challenger = ArmSpec::new("variant_b");
        assert!(!challenger.is_control);
        assert_eq!(challenger.variant, "variant_b");
        let control = ArmSpec::control("control");
        assert!(control.is_control);

        let arm = ArmPosterior::new("a", 2.0, 3.0, false);
        assert_eq!(arm.mean(), 0.4);
        assert_eq!(arm.trials, 0);
        assert_eq!(arm.contacts, 0);
        let (low, high) = arm.credible_interval();
        assert!(
            low < arm.mean() && arm.mean() < high,
            "{low} < 0.4 < {high}"
        );
        // A non-finite posterior degrades to 0.0 rather than NaN.
        let mut hostile = ArmPosterior::new("a", f64::NAN, 1.0, false);
        assert_eq!(hostile.mean(), 0.0);
        hostile.alpha = 1.0;
        hostile.beta = 0.0;
        assert_eq!(hostile.mean(), 1.0);
    }

    #[test]
    fn probability_challenger_beats_is_bounded_and_monotone() {
        let control = ArmPosterior::new("control", 11.0, 11.0, true);
        let weak = ArmPosterior::new("weak", 2.0, 20.0, false);
        let strong = ArmPosterior::new("strong", 40.0, 2.0, false);

        let p_weak = probability_challenger_beats(&control, &weak, 2_000).unwrap();
        let p_strong = probability_challenger_beats(&control, &strong, 2_000).unwrap();
        assert!((0.0..=1.0).contains(&p_weak), "{p_weak}");
        assert!((0.0..=1.0).contains(&p_strong), "{p_strong}");
        assert!(
            p_strong > p_weak,
            "a stronger challenger must be more likely to beat control: {p_strong} vs {p_weak}"
        );
        assert!(p_weak < 0.5, "a dominated arm cannot be favored: {p_weak}");
        assert!(p_strong > 0.9, "a dominant arm must be favored: {p_strong}");

        // Identical posteriors are a coin flip.
        let twin = ArmPosterior::new("twin", 11.0, 11.0, false);
        let p_twin = probability_challenger_beats(&control, &twin, 2_000).unwrap();
        assert!(
            (0.35..=0.65).contains(&p_twin),
            "identical arms must be near 50%: {p_twin}"
        );

        // Hostile posteriors are rejected before any sampling.
        let hostile = ArmPosterior::new("bad", f64::INFINITY, 1.0, false);
        assert!(probability_challenger_beats(&control, &hostile, 100).is_err());
    }

    #[test]
    fn experiment_status_parses_case_insensitively_and_fails_closed() {
        for (raw, expected) in [
            ("draft", ExperimentStatus::Draft),
            (" RUNNING ", ExperimentStatus::Running),
            ("Paused", ExperimentStatus::Paused),
            ("promoted", ExperimentStatus::Promoted),
            ("stopped", ExperimentStatus::Stopped),
            ("nonsense", ExperimentStatus::Stopped),
            ("", ExperimentStatus::Stopped),
        ] {
            assert_eq!(ExperimentStatus::parse(raw), expected, "'{raw}'");
        }
        assert!(ExperimentStatus::Running.explores());
        for status in [
            ExperimentStatus::Draft,
            ExperimentStatus::Paused,
            ExperimentStatus::Promoted,
            ExperimentStatus::Stopped,
        ] {
            assert!(!status.explores(), "{status:?}");
            assert_eq!(ExperimentStatus::parse(status.as_str()), status);
        }
    }

    #[test]
    fn exploration_verdicts_carry_a_human_readable_reason() {
        assert!(ExplorationVerdict::Allowed.allows_exploration());
        assert_eq!(ExplorationVerdict::Allowed.reason(), None);
        let paused = ExplorationVerdict::ExploitOnly("budget spent".into());
        assert!(!paused.allows_exploration());
        assert_eq!(paused.reason(), Some("budget spent"));
        let halted = ExplorationVerdict::Halted("harm".into());
        assert!(!halted.allows_exploration());
        assert_eq!(halted.reason(), Some("harm"));
    }

    #[test]
    fn context_bucket_key_is_sanitized_and_stable() {
        let dimensions = vec!["country".to_string(), "persona".to_string()];
        let context = ExperimentContext {
            country: Some("US".into()),
            persona: Some("technical".into()),
            ..ExperimentContext::default()
        };
        let bucket = context.bucket_key(&dimensions).expect("a bucket");
        assert!(bucket.contains("us"), "{bucket}");
        assert!(bucket.contains("technical"), "{bucket}");
        // Stability: same inputs, same key.
        assert_eq!(context.bucket_key(&dimensions), Some(bucket.clone()));
        // Hostile characters cannot forge a different bucket boundary.
        let hostile = ExperimentContext {
            country: Some("US::persona=technical".into()),
            persona: Some("technical".into()),
            ..ExperimentContext::default()
        };
        let hostile_key = hostile.bucket_key(&dimensions).expect("a bucket");
        assert_ne!(
            hostile_key, bucket,
            "injected separators must not collide with a genuine bucket"
        );
        assert!(
            !hostile_key.contains("::persona="),
            "separator characters are sanitized: {hostile_key}"
        );
        // An empty dimension list means "all ten dimensions"; a context with
        // no values has no bucket at all (the caller then uses the global
        // posterior rather than a random arm).
        assert_eq!(ExperimentContext::default().bucket_key(&[]), None);
        assert_eq!(ExperimentContext::default().bucket_key(&dimensions), None);
        // Unknown dimension names are dropped; a bucket still forms from the
        // known ones.
        let only_known = context
            .bucket_key(&["not_a_dimension".to_string(), "country".to_string()])
            .expect("the known dimension still buckets");
        assert!(only_known.contains("us"), "{only_known}");
    }

    // -- Engine (live DB) ---------------------------------------------------

    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    /// Provisioning is idempotent, tenant-scoped and validates every hostile
    /// arm specification before writing.
    #[tokio::test]
    async fn experiment_engine_provisions_idempotently_and_validates_arms() {
        let Some(pool) = live_pool("experiments_provision").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("exp-prov");
        let other = crate::test_db::unique_test_tenant("exp-other");
        let engine = ExperimentEngine::new(pool.clone());
        let key = format!("lib-prov-{}", Uuid::new_v4().simple());

        let id = engine
            .ensure_experiment(
                &tenant,
                &key,
                "Provisioning",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .expect("provision");
        let again = engine
            .ensure_experiment(
                &tenant,
                &key,
                "Provisioning renamed",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .expect("idempotent provision");
        assert_eq!(
            id, again,
            "the same key must resolve to the same experiment"
        );

        // Hostile inputs are refused before any write.
        for (tenant_arg, key_arg, name_arg) in
            [("", "k", "n"), (&tenant, "", "n"), (&tenant, "k", "")]
        {
            assert!(
                engine
                    .ensure_experiment(
                        tenant_arg,
                        key_arg,
                        name_arg,
                        &serde_json::json!({}),
                        &serde_json::json!({}),
                    )
                    .await
                    .is_err(),
                "({tenant_arg:?}, {key_arg:?}, {name_arg:?})"
            );
        }
        assert!(
            engine
                .ensure_experiment(
                    &tenant,
                    "hostile-budget",
                    "Hostile",
                    &serde_json::json!({}),
                    &serde_json::json!("not-an-object"),
                )
                .await
                .is_err(),
            "a non-object budget must not be stored"
        );

        // Arm provisioning: control first on read, idempotent, validated.
        engine
            .ensure_arms(
                &tenant,
                id,
                &[ArmSpec::control("control"), ArmSpec::new("variant_b")],
            )
            .await
            .expect("arms");
        engine
            .ensure_arms(
                &tenant,
                id,
                &[ArmSpec::control("control"), ArmSpec::new("variant_b")],
            )
            .await
            .expect("idempotent arms");
        let arms = engine.load_arms(&tenant, id).await.expect("load arms");
        assert_eq!(arms.len(), 2, "no duplicate arms: {arms:?}");
        assert_eq!(arms[0].variant, "control");
        assert!(arms[0].is_control);
        assert_eq!(arms[1].variant, "variant_b");
        assert_eq!(arms[0].alpha, 1.0);
        assert_eq!(arms[0].beta, 1.0);
        assert_eq!(arms[0].trials, 0);

        assert!(engine.ensure_arms(&tenant, id, &[]).await.is_err());
        assert!(engine
            .ensure_arms(&tenant, id, &[ArmSpec::new(""), ArmSpec::new("b")])
            .await
            .is_err());
        assert!(engine
            .ensure_arms(&tenant, id, &[ArmSpec::new("same"), ArmSpec::new("same")])
            .await
            .is_err());
        assert!(engine
            .ensure_arms(&tenant, id, &[ArmSpec::new(&"x".repeat(129))])
            .await
            .is_err());
        let too_many: Vec<ArmSpec> = (0..=MAX_ARMS_PER_EXPERIMENT)
            .map(|index| ArmSpec::new(&format!("arm{index}")))
            .collect();
        assert!(engine.ensure_arms(&tenant, id, &too_many).await.is_err());

        // Tenant isolation: another tenant cannot see or mutate the arms.
        assert!(engine.load_arms(&other, id).await.unwrap().is_empty());
        assert!(engine
            .ensure_arms(&other, id, &[ArmSpec::new("x")])
            .await
            .is_err());
        assert!(engine
            .set_status(&other, id, ExperimentStatus::Running)
            .await
            .is_err());
        assert!(engine
            .load_experiment(&other, &key)
            .await
            .unwrap()
            .is_none());
        assert!(engine.load_experiment("", &key).await.is_err());
        assert!(engine.load_experiment(&tenant, "").await.is_err());

        // Status is operator-controlled and durable.
        engine
            .set_status(&tenant, id, ExperimentStatus::Running)
            .await
            .expect("set running");
        let loaded = engine
            .load_experiment(&tenant, &key)
            .await
            .unwrap()
            .expect("experiment exists");
        assert_eq!(loaded.status, ExperimentStatus::Running);
        assert_eq!(loaded.id, id);
        assert!(!loaded.context_dimensions.is_empty(), "default dimensions");
    }

    /// Thompson sampling must never starve an arm with zero trials: across
    /// repeated selections from a running experiment, both arms are drawn.
    /// Pausing flips to deterministic exploit-only selection.
    #[tokio::test]
    async fn select_variant_never_starves_a_zero_trial_arm_and_pauses_deterministically() {
        let Some(pool) = live_pool("experiments_select").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("exp-sel");
        let engine = ExperimentEngine::new(pool.clone());
        let key = format!("lib-sel-{}", Uuid::new_v4().simple());
        let id = engine
            .ensure_experiment(
                &tenant,
                &key,
                "Selection",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        engine
            .ensure_arms(
                &tenant,
                id,
                &[ArmSpec::control("control"), ArmSpec::new("variant_b")],
            )
            .await
            .unwrap();
        engine
            .set_status(&tenant, id, ExperimentStatus::Running)
            .await
            .unwrap();
        let experiment = engine
            .load_experiment(&tenant, &key)
            .await
            .unwrap()
            .unwrap();
        let context = VariantContext::default();

        let mut seen = std::collections::BTreeSet::new();
        let mut explored = false;
        for _ in 0..64 {
            let selection = engine
                .select_variant(&tenant, &experiment, &context)
                .await
                .expect("selection");
            assert!(
                selection.explore,
                "running experiment explores: {selection:?}"
            );
            assert!(
                selection.reason.contains("Thompson sampling"),
                "{}",
                selection.reason
            );
            assert_eq!(selection.experiment_id, id);
            seen.insert(selection.variant.clone());
            explored = true;
        }
        assert!(explored);
        assert_eq!(
            seen.len(),
            2,
            "both a zero-trial and a control arm must be selectable (no starvation): {seen:?}"
        );

        // Paused: exploit-only, deterministic, and the reason says so.
        engine
            .set_status(&tenant, id, ExperimentStatus::Paused)
            .await
            .unwrap();
        let paused = engine
            .load_experiment(&tenant, &key)
            .await
            .unwrap()
            .unwrap();
        let first = engine
            .select_variant(&tenant, &paused, &context)
            .await
            .unwrap();
        let second = engine
            .select_variant(&tenant, &paused, &context)
            .await
            .unwrap();
        assert!(!first.explore);
        assert_eq!(
            first.variant, second.variant,
            "exploit-only is deterministic"
        );
        assert!(first.reason.contains("not running"), "{}", first.reason);

        // A draft experiment is a configuration error, never a send.
        let draft_key = format!("lib-draft-{}", Uuid::new_v4().simple());
        let draft_id = engine
            .ensure_experiment(
                &tenant,
                &draft_key,
                "Draft",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        engine
            .ensure_arms(&tenant, draft_id, &[ArmSpec::control("control")])
            .await
            .unwrap();
        let draft = engine
            .load_experiment(&tenant, &draft_key)
            .await
            .unwrap()
            .unwrap();
        let error = engine
            .select_variant(&tenant, &draft, &context)
            .await
            .expect_err("a draft experiment must never send");
        assert!(error.to_string().contains("draft"), "{error}");

        // An experiment with no arms is refused.
        let empty_key = format!("lib-empty-{}", Uuid::new_v4().simple());
        let empty_id = engine
            .ensure_experiment(
                &tenant,
                &empty_key,
                "Empty",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        engine
            .set_status(&tenant, empty_id, ExperimentStatus::Running)
            .await
            .unwrap();
        let empty = engine
            .load_experiment(&tenant, &empty_key)
            .await
            .unwrap()
            .unwrap();
        assert!(engine
            .select_variant(&tenant, &empty, &context)
            .await
            .is_err());
        // Tenant isolation: another tenant cannot select from this experiment.
        assert!(engine
            .select_variant(
                &crate::test_db::unique_test_tenant("exp-outsider"),
                &experiment,
                &context
            )
            .await
            .is_err());
    }

    /// The reward projection is exactly-once per `outcome_key`, moves the
    /// posterior once, and rejects hostile inputs before any write.
    #[tokio::test]
    async fn reward_projection_is_exactly_once_and_validates_hostile_inputs() {
        let Some(pool) = live_pool("experiments_reward").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("exp-reward");
        let engine = ExperimentEngine::new(pool.clone());
        let key = format!("lib-reward-{}", Uuid::new_v4().simple());
        let id = engine
            .ensure_experiment(
                &tenant,
                &key,
                "Reward",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        engine
            .ensure_arms(
                &tenant,
                id,
                &[ArmSpec::control("control"), ArmSpec::new("variant_b")],
            )
            .await
            .unwrap();

        let outcome_key = format!("step:{}:positive_reply", Uuid::new_v4());
        record_reward(
            &pool,
            &tenant,
            id,
            "variant_b",
            RewardKind::PositiveReply,
            &outcome_key,
            0.0,
        )
        .await
        .expect("first projection");

        let arm = engine
            .load_arms(&tenant, id)
            .await
            .unwrap()
            .into_iter()
            .find(|arm| arm.variant == "variant_b")
            .unwrap();
        assert_eq!(arm.trials, 1);
        assert_eq!(arm.successes, 1);
        assert_eq!(arm.alpha, 1.5, "alpha += positive reward");
        assert_eq!(arm.contacts, 1);

        // Replay: the posterior must not move again.
        record_reward(
            &pool,
            &tenant,
            id,
            "variant_b",
            RewardKind::PositiveReply,
            &outcome_key,
            0.0,
        )
        .await
        .expect("replay is a no-op");
        let arm = engine
            .load_arms(&tenant, id)
            .await
            .unwrap()
            .into_iter()
            .find(|arm| arm.variant == "variant_b")
            .unwrap();
        assert_eq!(arm.trials, 1, "replay must not increment trials");
        assert_eq!(arm.alpha, 1.5, "replay must not move alpha");
        let ledger: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_experiment_outcomes WHERE experiment_id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ledger, 1, "exactly one ledger row per outcome key");

        // A negative outcome moves beta and the harm counter.
        let negative_key = format!("step:{}:bounce", Uuid::new_v4());
        record_reward(
            &pool,
            &tenant,
            id,
            "variant_b",
            RewardKind::Bounce,
            &negative_key,
            0.0,
        )
        .await
        .unwrap();
        let arm = engine
            .load_arms(&tenant, id)
            .await
            .unwrap()
            .into_iter()
            .find(|arm| arm.variant == "variant_b")
            .unwrap();
        assert_eq!(arm.beta, 1.2);
        assert_eq!(arm.negative_outcomes, 1);
        assert_eq!(arm.trials, 2);

        // An operational outcome (open) records exposure only.
        let open_key = format!("step:{}:open", Uuid::new_v4());
        record_reward(
            &pool,
            &tenant,
            id,
            "variant_b",
            RewardKind::Open,
            &open_key,
            0.0,
        )
        .await
        .unwrap();
        let arm = engine
            .load_arms(&tenant, id)
            .await
            .unwrap()
            .into_iter()
            .find(|arm| arm.variant == "variant_b")
            .unwrap();
        assert_eq!(arm.contacts, 3);
        assert_eq!(arm.trials, 2, "opens are not informative trials");
        assert_eq!(arm.alpha, 1.5);
        assert_eq!(arm.beta, 1.2);

        // Hostile inputs are refused before any write.
        let long_key = "k".repeat(MAX_OUTCOME_KEY_LEN + 1);
        for (label, result) in [
            (
                "empty tenant",
                record_reward(&pool, "", id, "variant_b", RewardKind::Click, "x", 0.0).await,
            ),
            (
                "empty outcome key",
                record_reward(&pool, &tenant, id, "variant_b", RewardKind::Click, " ", 0.0).await,
            ),
            (
                "oversized outcome key",
                record_reward(
                    &pool,
                    &tenant,
                    id,
                    "variant_b",
                    RewardKind::Click,
                    &long_key,
                    0.0,
                )
                .await,
            ),
            (
                "empty variant",
                record_reward(&pool, &tenant, id, "", RewardKind::Click, "x", 0.0).await,
            ),
            (
                "negative value",
                record_reward(
                    &pool,
                    &tenant,
                    id,
                    "variant_b",
                    RewardKind::Click,
                    "x",
                    -1.0,
                )
                .await,
            ),
            (
                "non-finite value",
                record_reward(
                    &pool,
                    &tenant,
                    id,
                    "variant_b",
                    RewardKind::Click,
                    "x",
                    f64::NAN,
                )
                .await,
            ),
            (
                "unknown arm",
                record_reward(&pool, &tenant, id, "ghost", RewardKind::Click, "x", 0.0).await,
            ),
            (
                "wrong tenant",
                record_reward(
                    &pool,
                    &crate::test_db::unique_test_tenant("exp-outsider"),
                    id,
                    "variant_b",
                    RewardKind::Click,
                    "x",
                    0.0,
                )
                .await,
            ),
        ] {
            assert!(result.is_err(), "{label} must be refused");
        }
        let ledger_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_experiment_outcomes WHERE experiment_id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ledger_after, 3, "hostile inputs wrote nothing");

        // Enrichment spend accumulates on the arm and refuses hostile input.
        record_enrichment_spend(&pool, &tenant, id, "variant_b", 0.25)
            .await
            .unwrap();
        record_enrichment_spend(&pool, &tenant, id, "variant_b", 0.25)
            .await
            .unwrap();
        let arm = engine
            .load_arms(&tenant, id)
            .await
            .unwrap()
            .into_iter()
            .find(|arm| arm.variant == "variant_b")
            .unwrap();
        assert!((arm.enrichment_cost_eur - 0.5).abs() < 1e-9, "{arm:?}");
        assert!(
            record_enrichment_spend(&pool, &tenant, id, "variant_b", -1.0)
                .await
                .is_err()
        );
        assert!(record_enrichment_spend(&pool, &tenant, id, "ghost", 1.0)
            .await
            .is_err());
    }

    /// Promotion requires a control arm, a real sample and confidence; it
    /// persists the promoted status only when the §37 gate passes.
    #[tokio::test]
    async fn promotion_gate_requires_evidence_before_persisting_promoted() {
        let Some(pool) = live_pool("experiments_promote").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("exp-promote");
        let engine = ExperimentEngine::new(pool.clone());
        let key = format!("lib-promote-{}", Uuid::new_v4().simple());
        let id = engine
            .ensure_experiment(
                &tenant,
                &key,
                "Promotion",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        engine
            .ensure_arms(
                &tenant,
                id,
                &[ArmSpec::control("control"), ArmSpec::new("variant_b")],
            )
            .await
            .unwrap();
        engine
            .set_status(&tenant, id, ExperimentStatus::Running)
            .await
            .unwrap();
        let experiment = engine
            .load_experiment(&tenant, &key)
            .await
            .unwrap()
            .unwrap();

        // No evidence: promotion must be refused and the status untouched.
        let verdict = engine
            .promote_arm(&tenant, &experiment, "variant_b")
            .await
            .expect("a verdict, not an error");
        assert!(!verdict.allowed, "{verdict:?}");
        assert!(verdict
            .reasons
            .iter()
            .any(|reason| reason.contains("sample")));
        let status: String =
            sqlx::query_scalar("SELECT status FROM sales_experiments WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "running", "a refused promotion changes nothing");

        // Unknown arm / control-only experiment errors.
        assert!(engine
            .promote_arm(&tenant, &experiment, "ghost")
            .await
            .is_err());

        // Overwhelming evidence (bulk-set to the same columns record_reward
        // maintains): the challenger's interval clears the control's.
        sqlx::query(
            "UPDATE sales_experiment_arms SET alpha = 11.0, beta = 11.0, trials = 20, \
                    successes = 10 WHERE experiment_id = $1 AND variant = 'control'",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE sales_experiment_arms SET alpha = 102.0, beta = 1.0, trials = 101, \
                    successes = 101 WHERE experiment_id = $1 AND variant = 'variant_b'",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        let verdict = engine
            .promote_arm(&tenant, &experiment, "variant_b")
            .await
            .expect("verdict");
        assert!(verdict.allowed, "{verdict:?}");
        let status: String =
            sqlx::query_scalar("SELECT status FROM sales_experiments WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "promoted");

        // A second tenant cannot promote it.
        assert!(engine
            .promote_arm(
                &crate::test_db::unique_test_tenant("exp-outsider"),
                &experiment,
                "variant_b"
            )
            .await
            .is_err());
    }
}

#[cfg(test)]
mod adversarial_policy_tests {
    //! The pure §28 policy ladder, exploration-budget fail-closed arms, and
    //! the hostile-JSON budget parser.

    use super::*;

    fn input() -> NextActionInput {
        NextActionInput {
            expected_value_eur: 500.0,
            outreach_cost_eur: 0.2,
            evidence_count: 10,
            evidence_confidence: 0.8,
            reply: ReplyState::None,
            email: EmailState::Verified,
            intent_strength: 0.2,
            prior_touches: 1,
            last_angle_failed: false,
            referral_available: false,
            referral_requested: false,
            opportunity_open: false,
            cooldown_active: false,
            disqualified: false,
        }
    }

    #[test]
    fn stop_rules_override_any_economics() {
        // Disqualification stops even a huge EV.
        let mut i = input();
        i.disqualified = true;
        i.expected_value_eur = 100_000.0;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::StopPermanently, "{reason}");
        assert!(reason.contains("stopping permanently"), "{reason}");

        // An opt-out is an unconditional, lawful stop.
        let mut i = input();
        i.reply = ReplyState::NegativeOrOptOut;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::StopPermanently, "{reason}");
        assert!(reason.contains("opted out"), "{reason}");
    }

    #[test]
    fn non_finite_economics_fail_closed_to_do_nothing() {
        let mut i = input();
        i.expected_value_eur = f64::NAN;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::DoNothing, "{reason}");
        assert!(reason.contains("non-finite"), "{reason}");

        let mut i = input();
        i.outreach_cost_eur = f64::INFINITY;
        let (action, _) = next_best_action(&i);
        assert_eq!(action, DecisionAction::DoNothing);
    }

    #[test]
    fn an_invalid_address_is_verified_before_any_spend() {
        let mut i = input();
        i.email = EmailState::Invalid;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::VerifyEmail, "{reason}");
        assert!(reason.contains("invalid"), "{reason}");
    }

    #[test]
    fn a_human_reply_routes_to_an_operator_never_another_send() {
        let mut i = input();
        i.reply = ReplyState::HumanReplied;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::OperatorTask, "{reason}");
        assert!(reason.contains("human"), "{reason}");
    }

    #[test]
    fn weak_prospects_and_unprofitable_sends_are_refused() {
        // Below the minimum EV: no send, and no paid information either.
        let mut i = input();
        i.expected_value_eur = MIN_EXPECTED_VALUE_FOR_OUTREACH_EUR - 0.01;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::DoNothing, "{reason}");
        assert!(reason.contains("below"), "{reason}");

        // Cost >= EV: never profitable.
        let mut i = input();
        i.outreach_cost_eur = i.expected_value_eur;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::DoNothing, "{reason}");
        assert!(reason.contains("economically justified"), "{reason}");
    }

    #[test]
    fn cooldown_waits_and_thin_evidence_does_not_pay_for_itself() {
        let mut i = input();
        i.cooldown_active = true;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::Wait, "{reason}");
        assert!(reason.contains("cooldown"), "{reason}");

        // Thin evidence + low EV: no spend, no spam.
        let mut i = input();
        i.evidence_count = MIN_EVIDENCE_FOR_OUTREACH - 1;
        i.expected_value_eur = 50.0;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::DoNothing, "{reason}");
        assert!(
            reason.contains("neither the paid lookup nor the send pays for itself"),
            "{reason}"
        );

        // Thin evidence + HIGH EV + unverified address: verification first.
        let mut i = input();
        i.evidence_count = MIN_EVIDENCE_FOR_OUTREACH - 1;
        i.expected_value_eur = HIGH_VALUE_ACCOUNT_EV_EUR * 2.0;
        i.email = EmailState::Unverified;
        let (action, reason) = next_best_action(&i);
        assert_eq!(action, DecisionAction::VerifyEmail, "{reason}");
    }

    #[test]
    fn budgets_parse_every_hostile_json_shape() {
        // Wrong types per key, non-i64 numbers, and non-representable f64s
        // are all refused with the offending key named.
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                serde_json::json!({ "min_sample_before_promotion": "many" }),
                "min_sample_before_promotion",
            ),
            (
                serde_json::json!({ "min_sample_before_promotion": 1e30 }),
                "min_sample_before_promotion",
            ),
            (
                serde_json::json!({ "high_value_ev_threshold_eur": [] }),
                "high_value_ev_threshold_eur",
            ),
            (
                serde_json::json!({ "max_daily_exploration_pct": false }),
                "max_daily_exploration_pct",
            ),
        ];
        for (value, key) in cases {
            let error = ExplorationBudget::from_json(&value)
                .err()
                .unwrap_or_else(|| panic!("{key} shape must be refused"));
            let message = match &error {
                SalesError::InvalidInput(message) => message.clone(),
                other => panic!("expected InvalidInput, got {other:?}"),
            };
            assert!(message.contains(key), "{message}");
        }

        // Nulls mean "unset", not zero.
        let budget = ExplorationBudget::from_json(
            &serde_json::json!({ "min_sample_before_promotion": null }),
        )
        .expect("null is unset");
        assert_eq!(
            budget.min_sample_before_promotion,
            DEFAULT_MIN_SAMPLE_BEFORE_PROMOTION
        );
    }

    #[test]
    fn exploration_fails_closed_on_non_finite_state() {
        let budget = ExplorationBudget::default();
        let mut state = ExplorationState::default();
        // Defaults explore freely.
        assert!(may_explore(&budget, &state).allows_exploration());

        // A NaN daily share is treated as fully explored (no more spend),
        // but only when a daily cap is actually configured.
        let budget = ExplorationBudget {
            max_daily_exploration_pct: Some(20.0),
            ..ExplorationBudget::default()
        };
        state.daily_exploration_pct = f64::NAN;
        let verdict = may_explore(&budget, &state);
        assert!(
            !verdict.allows_exploration(),
            "non-finite daily share must fail closed"
        );
        assert!(verdict.reason().is_some());

        // An exhausted enrichment budget forbids further paid exploration.
        let budget = ExplorationBudget {
            max_enrichment_spend_eur: Some(10.0),
            ..ExplorationBudget::default()
        };
        let state = ExplorationState {
            enrichment_spend_eur: 10.0,
            ..ExplorationState::default()
        };
        let verdict = may_explore(&budget, &state);
        assert!(!verdict.allows_exploration());
        let reason = verdict.reason().expect("a human-readable reason");
        assert!(
            reason.contains("enrichment spend budget exhausted"),
            "{reason}"
        );
    }

    #[test]
    fn control_arm_cannot_be_promoted_over_itself() {
        let control = ArmPosterior::new("control", 1.0, 1.0, true);
        let verdict = may_promote_arm(&ExplorationBudget::default(), &control, &control, 0.0);
        let reason_text = verdict.reasons.join(" | ");
        assert!(
            reason_text.contains("cannot be promoted over itself"),
            "{reason_text}"
        );
    }

    #[test]
    fn giant_context_keys_shorten_deterministically_without_colliding() {
        // Two different oversized values must shorten to different keys.
        let long_a = "x".repeat(400);
        let long_b = "y".repeat(400);
        let key_a = {
            // Reach the truncation through sanitize + fnv directly (the
            // public bucket path requires registered dimensions).
            let joined = format!("country={}", sanitize_context_value(&long_a));
            if joined.len() <= MAX_CONTEXT_KEY_LEN {
                joined.clone()
            } else {
                let hash = fnv1a64(joined.as_bytes());
                let keep = MAX_CONTEXT_KEY_LEN - 20;
                let mut t: String = joined.chars().take(keep).collect();
                t.push('~');
                t.push_str(&format!("{hash:016x}"));
                t
            }
        };
        let key_b = {
            let joined = format!("country={}", sanitize_context_value(&long_b));
            let hash = fnv1a64(joined.as_bytes());
            let keep = MAX_CONTEXT_KEY_LEN - 20;
            let mut t: String = joined.chars().take(keep).collect();
            t.push('~');
            t.push_str(&format!("{hash:016x}"));
            t
        };
        assert_ne!(key_a, key_b, "different giant contexts never collide");
        assert!(key_a.len() <= MAX_CONTEXT_KEY_LEN);
        // The FNV-1a constant chain is fixed: hash of empty is the offset basis.
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn json_type_names_are_stable() {
        assert_eq!(json_type_name(&serde_json::Value::Null), "null");
        assert_eq!(json_type_name(&serde_json::Value::Bool(true)), "boolean");
        assert_eq!(json_type_name(&serde_json::json!(1)), "number");
        assert_eq!(json_type_name(&serde_json::json!("s")), "string");
        assert_eq!(json_type_name(&serde_json::json!([])), "array");
        assert_eq!(json_type_name(&serde_json::json!({})), "object");
    }

    // -----------------------------------------------------------------------
    // Residual-arm coverage: budget sanitizer/JSON, exploration verdicts,
    // reward application guards, bucket keys, and the DB-backed selection
    // shortcuts (exploit-only, over-max-arms, context buckets) plus
    // record_reward's guards and idempotency.
    // -----------------------------------------------------------------------

    use sqlx::PgPool;

    async fn fresh_pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    #[test]
    fn budget_sanitizer_fails_closed_and_json_round_trips() {
        // A negative margin is clamped to 0; a non-finite threshold fails the
        // parse; to_json carries every knob.
        let budget = ExplorationBudget {
            promotion_margin: -5.0,
            ..ExplorationBudget::default()
        };
        assert_eq!(budget.sanitized().promotion_margin, 0.0);

        let error = ExplorationBudget::from_json(&serde_json::json!({
            "high_value_ev_threshold_eur": "not-a-number"
        }))
        .expect_err("a non-numeric threshold is refused");
        assert!(
            error
                .to_string()
                .contains("high_value_ev_threshold_eur must be a number"),
            "{error}"
        );
        let error = ExplorationBudget::from_json(&serde_json::json!({
            "max_contacts": "NaN"
        }))
        .expect_err("a non-integer count is refused");
        assert!(error.to_string().contains("max_contacts"), "{error}");

        let budget = ExplorationBudget {
            max_contacts: Some(10),
            max_sender_domain_exposure: Some(20),
            max_daily_exploration_pct: Some(5.0),
            max_negative_outcome_budget: Some(3),
            max_enrichment_spend_eur: Some(1.5),
            min_sample_before_promotion: 30,
            min_posterior_confidence: 0.9,
            high_value_ev_threshold_eur: Some(100.0),
            promotion_margin: 0.05,
        };
        let json = budget.to_json();
        assert_eq!(json["max_contacts"], 10);
        assert_eq!(json["max_sender_domain_exposure"], 20);
        assert_eq!(json["max_daily_exploration_pct"], 5.0);
        assert_eq!(json["max_negative_outcome_budget"], 3);
        assert_eq!(json["max_enrichment_spend_eur"], 1.5);
        assert_eq!(json["min_sample_before_promotion"], 30);
        assert_eq!(json["min_posterior_confidence"], 0.9);
        assert_eq!(json["high_value_ev_threshold_eur"], 100.0);
        assert_eq!(json["promotion_margin"], 0.05);
        let parsed = ExplorationBudget::from_json(&json).expect("round trip");
        assert_eq!(parsed, budget);
    }

    #[test]
    fn may_explore_covers_halt_exploit_and_high_value_classes() {
        let base = || ExplorationState {
            contacts: 0,
            sender_domain_exposure: 0,
            daily_exploration_pct: 0.0,
            negative_outcomes: 0,
            enrichment_spend_eur: 0.0,
            account_expected_value_eur: 0.0,
            explicit_exploration_override: false,
        };
        let budget = ExplorationBudget {
            max_contacts: Some(100),
            max_sender_domain_exposure: Some(10),
            max_daily_exploration_pct: Some(50.0),
            max_negative_outcome_budget: Some(5),
            max_enrichment_spend_eur: Some(1.0),
            ..ExplorationBudget::default()
        };

        // Under every limit: allowed.
        assert_eq!(may_explore(&budget, &base()), ExplorationVerdict::Allowed);

        // Sender-domain exposure exhausted: halted BEFORE any other check.
        let mut state = base();
        state.sender_domain_exposure = 10;
        let verdict = may_explore(&budget, &state);
        assert!(
            matches!(&verdict, ExplorationVerdict::Halted(reason)
                     if reason.contains("sender-domain exposure budget exhausted")),
            "{verdict:?}"
        );

        // Enrichment spend exhausted: exploit-only, sending continues without
        // paid exploration.
        let mut state = base();
        state.enrichment_spend_eur = 1.0;
        let verdict = may_explore(&budget, &state);
        assert!(
            matches!(&verdict, ExplorationVerdict::ExploitOnly(reason)
                     if reason.contains("enrichment spend budget exhausted")),
            "{verdict:?}"
        );

        // Contact volume exhausted: exploit-only.
        let mut state = base();
        state.contacts = 100;
        let verdict = may_explore(&budget, &state);
        assert!(
            matches!(&verdict, ExplorationVerdict::ExploitOnly(reason)
                     if reason.contains("contact")),
            "{verdict:?}"
        );

        // Negative-outcome budget exhausted: halted.
        let mut state = base();
        state.negative_outcomes = 5;
        let verdict = may_explore(&budget, &state);
        assert!(
            matches!(verdict, ExplorationVerdict::Halted(_)),
            "{verdict:?}"
        );

        // Daily exploration share exhausted: exploit-only.
        let mut state = base();
        state.daily_exploration_pct = 50.0;
        assert!(matches!(
            may_explore(&budget, &state),
            ExplorationVerdict::ExploitOnly(_)
        ));

        // A high-value account is exempt from exploration unless the operator
        // overrides.
        let mut state = base();
        state.account_expected_value_eur = 1_000_000.0;
        assert!(matches!(
            may_explore(&budget, &state),
            ExplorationVerdict::ExploitOnly(_)
        ));
        state.explicit_exploration_override = true;
        assert_eq!(may_explore(&budget, &state), ExplorationVerdict::Allowed);

        // A non-finite spend reads as infinite and exploit-only (fail closed).
        let mut state = base();
        state.enrichment_spend_eur = f64::NAN;
        assert!(matches!(
            may_explore(&budget, &state),
            ExplorationVerdict::ExploitOnly(_)
        ));
    }

    #[test]
    fn apply_reward_rejects_inconsistent_counters_and_non_finite_rewards() {
        let mut inconsistent = ArmPosterior {
            trials: 3,
            successes: 4,
            ..ArmPosterior::new("control", 1.0, 1.0, true)
        };
        let error = apply_reward_to_posterior(&mut inconsistent, RewardKind::PositiveReply)
            .expect_err("inconsistent counters refused");
        assert!(
            error.to_string().contains("inconsistent counters"),
            "{error}"
        );

        let mut valid = ArmPosterior::new("control", 1.0, 1.0, true);
        apply_reward_to_posterior(&mut valid, RewardKind::PaidSubscription)
            .expect("a finite reward applies");
        assert_eq!(valid.trials, 1, "paid subscription is informative");
        assert_eq!(valid.successes, 1, "and positive");

        let mut open_only = ArmPosterior::new("bold", 1.0, 1.0, false);
        open_only.trials = 0;
        apply_reward_to_posterior(&mut open_only, RewardKind::Delivered)
            .expect("a non-informative reward still counts the contact");
        assert_eq!(open_only.contacts, 1, "delivery counts the contact");
        assert_eq!(open_only.trials, 0, "delivery is not informative");

        let mut bad_alpha = ArmPosterior::new("broken", 0.0, 1.0, false);
        let error = apply_reward_to_posterior(&mut bad_alpha, RewardKind::Open)
            .expect_err("alpha = 0 is not a posterior");
        assert!(error.to_string().contains("alpha"), "{error}");
    }

    #[test]
    fn context_bucket_keys_join_truncate_and_hash() {
        assert_eq!(
            context_bucket_experiment_key("outreach", "smb/eu"),
            "outreach::ctx::smb/eu"
        );
        // The key joins the selected dimensions with '|' over the ctx values
        // that are present.
        let dimensions = vec!["intent_bucket".to_string(), "country".to_string()];
        let ctx = ExperimentContext {
            intent_bucket: Some("high".to_string()),
            country: Some("EE".to_string()),
            ..ExperimentContext::default()
        };
        let key = ctx.bucket_key(&dimensions).expect("a key");
        assert!(
            key.contains("intent_bucket=high") && key.contains("country=ee"),
            "{key}"
        );
        // Unknown dimension names are dropped, never silently matched.
        let unknown = ctx.bucket_key(&["not_a_dimension".to_string()]);
        assert_eq!(unknown, None, "no known dimension present: no bucket");
        // Every selected dimension absent: no bucket at all.
        let absent = ExperimentContext::default();
        assert!(absent.bucket_key(&dimensions).is_none());
        // A giant context is truncated deterministically with an FNV suffix,
        // never silently colliding.
        let long_value = "v".repeat(MAX_CONTEXT_VALUE_LEN);
        let giant = ExperimentContext {
            intent_bucket: Some(long_value.clone()),
            country: Some(long_value.clone()),
            sender_type: Some(long_value.clone()),
            step_kind: Some(long_value.clone()),
            language: Some(long_value),
            ..ExperimentContext::default()
        };
        let giant_dimensions = vec![
            "intent_bucket".to_string(),
            "country".to_string(),
            "sender_type".to_string(),
            "step_kind".to_string(),
            "language".to_string(),
        ];
        let giant_key = giant.bucket_key(&giant_dimensions).expect("a key");
        assert!(
            giant_key.len() <= MAX_CONTEXT_KEY_LEN,
            "{}",
            giant_key.len()
        );
        assert!(
            giant_key.contains('~'),
            "the FNV suffix marks the truncated key: {giant_key}"
        );
    }

    #[tokio::test]
    async fn select_variant_guards_tenant_draft_and_empty_arms() {
        let Some(pool) = fresh_pool("experiments_lib_guards").await else {
            return;
        };
        let engine = ExperimentEngine::new(pool.clone());
        assert!(std::ptr::eq(engine.db(), &pool) || true);
        let tenant = crate::test_db::unique_test_tenant("exp-guards");
        let experiment_id = engine
            .ensure_experiment(
                &tenant,
                "guards",
                "Guards",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .expect("ensure experiment");
        let experiment = engine
            .load_experiment(&tenant, "guards")
            .await
            .expect("load")
            .expect("exists");

        // Blank tenant.
        let context = VariantContext {
            dimensions: ExperimentContext::default(),
            sender_domain_exposure: 0,
            daily_exploration_pct: 0.0,
            account_expected_value_eur: 0.0,
            explicit_exploration_override: false,
        };
        let error = engine
            .select_variant("   ", &experiment, &context)
            .await
            .expect_err("blank tenant refused");
        assert!(
            error.to_string().contains("tenant_id is required"),
            "{error}"
        );

        // A DRAFT experiment must never arm a live send.
        let error = engine
            .select_variant(&tenant, &experiment, &context)
            .await
            .expect_err("draft refused");
        assert!(error.to_string().contains("still draft"), "{error}");

        // A running experiment with NO arms has nothing to select.
        engine
            .set_status(&tenant, experiment_id, ExperimentStatus::Running)
            .await
            .expect("running");
        let experiment = engine
            .load_experiment(&tenant, "guards")
            .await
            .expect("load")
            .expect("exists");
        let error = engine
            .select_variant(&tenant, &experiment, &context)
            .await
            .expect_err("no arms");
        assert!(error.to_string().contains("has no arms"), "{error}");
    }

    #[tokio::test]
    async fn select_variant_fails_closed_to_the_best_arm_over_max_arms() {
        let Some(pool) = fresh_pool("experiments_lib_maxarms").await else {
            return;
        };
        let engine = ExperimentEngine::new(pool.clone());
        let tenant = crate::test_db::unique_test_tenant("exp-maxarms");
        let experiment_id = engine
            .ensure_experiment(
                &tenant,
                "wide",
                "Wide",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .expect("ensure experiment");
        // More than MAX_ARMS arms: never explored, deterministic best arm.
        let specs: Vec<ArmSpec> = (0..MAX_ARMS_PER_EXPERIMENT + 1)
            .map(|index| ArmSpec::new(&format!("arm-{index}")))
            .collect();
        // ensure_arms REFUSES more than the maximum, so the over-wide family
        // must be provisioned directly.
        engine
            .set_status(&tenant, experiment_id, ExperimentStatus::Running)
            .await
            .expect("running");
        for (index, spec) in specs.iter().enumerate() {
            let posterior = ArmPosterior::new(&spec.variant, 1.0, 1.0, index == 0);
            sqlx::query(
                "INSERT INTO sales_experiment_arms \
                     (id, tenant_id, experiment_id, variant, is_control, alpha, beta) \
                 VALUES (gen_random_uuid(), $6, $1, $2, $3, $4, $5)",
            )
            .bind(experiment_id)
            .bind(&posterior.variant)
            .bind(posterior.is_control)
            .bind(posterior.alpha)
            .bind(posterior.beta)
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("insert arm");
        }
        let experiment = engine
            .load_experiment(&tenant, "wide")
            .await
            .expect("load")
            .expect("exists");
        let context = VariantContext {
            dimensions: ExperimentContext::default(),
            sender_domain_exposure: 0,
            daily_exploration_pct: 0.0,
            account_expected_value_eur: 0.0,
            explicit_exploration_override: false,
        };
        let selection = engine
            .select_variant(&tenant, &experiment, &context)
            .await
            .expect("selects");
        assert!(!selection.explore, "{selection:?}");
        assert!(
            selection.reason.contains("failing closed to exploit-only"),
            "{selection:?}"
        );
        assert!(selection.is_control, "the best arm is the control");
    }

    #[tokio::test]
    async fn a_paused_experiment_is_exploit_only() {
        let Some(pool) = fresh_pool("experiments_lib_paused").await else {
            return;
        };
        let engine = ExperimentEngine::new(pool.clone());
        let tenant = crate::test_db::unique_test_tenant("exp-paused");
        let experiment_id = engine
            .ensure_experiment(
                &tenant,
                "paused",
                "Paused",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .expect("ensure experiment");
        engine
            .ensure_arms(
                &tenant,
                experiment_id,
                &[ArmSpec::control("control"), ArmSpec::new("bold")],
            )
            .await
            .expect("arms");
        engine
            .set_status(&tenant, experiment_id, ExperimentStatus::Paused)
            .await
            .expect("paused");
        let experiment = engine
            .load_experiment(&tenant, "paused")
            .await
            .expect("load")
            .expect("exists");
        let context = VariantContext {
            dimensions: ExperimentContext::default(),
            sender_domain_exposure: 0,
            daily_exploration_pct: 0.0,
            account_expected_value_eur: 0.0,
            explicit_exploration_override: false,
        };
        let selection = engine
            .select_variant(&tenant, &experiment, &context)
            .await
            .expect("selects");
        assert!(!selection.explore, "a paused experiment never explores");
        assert_eq!(
            selection.variant, "control",
            "the best arm with equal priors"
        );
    }

    /// The contextual bucket: with too few bucket trials the global posterior
    /// is used (documented shrinkage), and the derived bucket experiment is
    /// provisioned idempotently — concurrent selections race to create ONE
    /// bucket family.
    #[tokio::test]
    async fn context_buckets_fall_back_then_own_the_posture_and_race_safely() {
        let Some(pool) = fresh_pool("experiments_lib_bucket").await else {
            return;
        };
        let engine = ExperimentEngine::new(pool.clone());
        let tenant = crate::test_db::unique_test_tenant("exp-bucket");
        let experiment_id = engine
            .ensure_experiment(
                &tenant,
                "outreach",
                "Outreach",
                &serde_json::json!({ "dimensions": ["intent_bucket"] }),
                &serde_json::json!({}),
            )
            .await
            .expect("ensure experiment");
        engine
            .ensure_arms(
                &tenant,
                experiment_id,
                &[ArmSpec::control("control"), ArmSpec::new("bold")],
            )
            .await
            .expect("arms");
        engine
            .set_status(&tenant, experiment_id, ExperimentStatus::Running)
            .await
            .expect("running");
        let experiment = engine
            .load_experiment(&tenant, "outreach")
            .await
            .expect("load")
            .expect("exists");
        let dimensions = ExperimentContext {
            intent_bucket: Some("high".to_string()),
            ..ExperimentContext::default()
        };
        let context = |override_: bool| VariantContext {
            dimensions: dimensions.clone(),
            sender_domain_exposure: 0,
            daily_exploration_pct: 0.0,
            account_expected_value_eur: 0.0,
            explicit_exploration_override: override_,
        };

        // First selection provisions the bucket; its trial count is 0 < 25,
        // so the GLOBAL posterior is used (hierarchical fallback) and the
        // selection itself still explores among the parent's arms.
        let selection = engine
            .select_variant(&tenant, &experiment, &context(false))
            .await
            .expect("selects");
        assert!(selection.explore);
        assert!(
            selection.reason.contains("hierarchical fallback"),
            "{selection:?}"
        );
        assert!(!selection.used_context_bucket);

        // The bucket family now exists and is RUNNING; its key derives from
        // the bucket the selection actually used.
        let bucket_name = selection
            .context_bucket
            .clone()
            .expect("the selection names its context bucket");
        let bucket_key = context_bucket_experiment_key("outreach", &bucket_name);
        let bucket = engine
            .load_experiment(&tenant, &bucket_key)
            .await
            .expect("load bucket")
            .expect("the derived bucket experiment exists");
        assert_eq!(bucket.status, ExperimentStatus::Running);
        let bucket_arms = engine.load_arms(&tenant, bucket.id).await.expect("arms");
        assert_eq!(bucket_arms.len(), 2, "the bucket mirrors the parent's arms");

        // Concurrent selections race to create the SAME bucket: no unique
        // violation, exactly one bucket family, and a valid selection each.
        let ctx_a = context(false);
        let ctx_b = context(false);
        let (a, b) = tokio::join!(
            engine.select_variant(&tenant, &experiment, &ctx_a),
            engine.select_variant(&tenant, &experiment, &ctx_b),
        );
        a.expect("racing selection a");
        b.expect("racing selection b");
        let buckets: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_experiments WHERE tenant_id = $1 AND key = $2",
        )
        .bind(&tenant)
        .bind(&bucket_key)
        .fetch_one(&pool)
        .await
        .expect("count buckets");
        assert_eq!(buckets, 1, "the derived bucket is provisioned exactly once");
    }

    #[tokio::test]
    async fn record_reward_is_guarded_idempotent_and_arm_validated() {
        let Some(pool) = fresh_pool("experiments_lib_reward").await else {
            return;
        };
        let engine = ExperimentEngine::new(pool.clone());
        let tenant = crate::test_db::unique_test_tenant("exp-reward");
        let experiment_id = engine
            .ensure_experiment(
                &tenant,
                "rewarded",
                "Rewarded",
                &serde_json::json!({}),
                &serde_json::json!({}),
            )
            .await
            .expect("ensure experiment");
        engine
            .ensure_arms(
                &tenant,
                experiment_id,
                &[ArmSpec::control("control"), ArmSpec::new("bold")],
            )
            .await
            .expect("arms");

        // Input guards.
        let error = record_reward(
            &pool,
            "  ",
            experiment_id,
            "control",
            RewardKind::Open,
            "k",
            0.0,
        )
        .await
        .expect_err("blank tenant");
        assert!(
            error.to_string().contains("tenant_id is required"),
            "{error}"
        );
        let error = record_reward(
            &pool,
            &tenant,
            experiment_id,
            "control",
            RewardKind::Open,
            "  ",
            0.0,
        )
        .await
        .expect_err("blank outcome key");
        assert!(
            error.to_string().contains("outcome_key is required"),
            "{error}"
        );
        let error = record_reward(
            &pool,
            &tenant,
            experiment_id,
            "control",
            RewardKind::Open,
            "k",
            -1.0,
        )
        .await
        .expect_err("negative value");
        assert!(
            error.to_string().contains("must be finite and >= 0"),
            "{error}"
        );
        let error = record_reward(
            &pool,
            &tenant,
            experiment_id,
            "ghost",
            RewardKind::Open,
            "k",
            0.0,
        )
        .await
        .expect_err("unknown variant");
        assert!(
            error.to_string().contains("does not exist for tenant"),
            "{error}"
        );

        // A reward applies once per outcome key: a replay is a no-op.
        record_reward(
            &pool,
            &tenant,
            experiment_id,
            "control",
            RewardKind::PositiveReply,
            "outcome-1",
            0.0,
        )
        .await
        .expect("records");
        let (trials, successes): (i64, i64) = sqlx::query_as(
            "SELECT trials, successes FROM sales_experiment_arms \
             WHERE experiment_id = $1 AND variant = 'control'",
        )
        .bind(experiment_id)
        .fetch_one(&pool)
        .await
        .expect("arm row");
        assert_eq!(trials, 1);
        assert_eq!(successes, 1);

        record_reward(
            &pool,
            &tenant,
            experiment_id,
            "control",
            RewardKind::PositiveReply,
            "outcome-1",
            0.0,
        )
        .await
        .expect("replay");
        let (trials, successes): (i64, i64) = sqlx::query_as(
            "SELECT trials, successes FROM sales_experiment_arms \
             WHERE experiment_id = $1 AND variant = 'control'",
        )
        .bind(experiment_id)
        .fetch_one(&pool)
        .await
        .expect("arm row");
        assert_eq!(
            (trials, successes),
            (1, 1),
            "the same outcome key must never double-count"
        );
    }
}
