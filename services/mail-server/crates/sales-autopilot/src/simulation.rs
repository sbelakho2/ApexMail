//! §35 — replay simulation that is not test-only: historical replay,
//! champion/challenger shadowing and the promotion registry.
//!
//! The previous version of this module was a `#[cfg(test)]` harness with mock
//! leads; that cannot validate a policy, because it never compares a proposed
//! decision with what reality did. This module now provides:
//!
//! * [`ReplayCase`] / [`load_replay_cases`] — historical decision points built
//!   from the canonical tables (account, contact, signals, evidence, policy
//!   decisions, prior outcomes) with the **realised** outcome attached;
//! * [`replay`] — a pure function that runs a [`Policy`] over the cases and
//!   reports agreement with reality, the action distribution and the signed
//!   expected-value error;
//! * [`shadow`] — champion/challenger comparison over the same cases;
//! * [`PolicyRegistry`] — a new scoring/model version may **not** immediately
//!   control live outbound: [`PolicyRegistry::stage`] refuses unless a
//!   completed shadow comparison over at least [`MIN_SHADOW_CASES`] cases
//!   exists, its calibration passes [`calibration::may_promote`], and it has
//!   spent at least [`MIN_DAYS_IN_SHADOW`] days in shadow.
//!
//! Agreement is measured against the documented reality mapping
//! [`realised_action_for`]: what a rational operator, knowing the outcome,
//! would have proposed at the decision point. It is deliberately coarse and
//! documented, not a secret heuristic.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::attribution::OutcomeKind;
use crate::calibration::{self, CalibrationReport};
use crate::experiments::{action_counts, DEFAULT_OUTREACH_COST_EUR};
use crate::scoring::{
    self, EeaRelevance, EmailStackFeatures, EvidenceFeatures, OutcomeFeatures,
    ReachabilityFeatures, RiskFeatures, ScoreFeatures, SegmentMatch,
};
use crate::signals::SignalObservation;
use crate::types::{ContactDecision, DecisionAction, SalesError};

/// Minimum shadow cases before a model version may go production.
pub const MIN_SHADOW_CASES: usize = 200;

/// Minimum days a version must spend in shadow before promotion.
pub const MIN_DAYS_IN_SHADOW: i64 = 7;

/// Minimum calibration observations accepted by the promotion gate.
pub const MIN_SHADOW_CALIBRATION_N: i64 = 100;

/// Maximum Brier score accepted by the promotion gate.
pub const MAX_SHADOW_BRIER: f64 = 0.25;

/// Default `load_replay_cases` limit.
pub const DEFAULT_REPLAY_LIMIT: i64 = 500;

/// Hard cap on `load_replay_cases` (bounded work per call).
pub const MAX_REPLAY_LIMIT: i64 = 5_000;

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// One historical decision point: the state at `as_of` plus what actually
/// happened next.
#[derive(Debug, Clone)]
pub struct ReplayCase {
    pub tenant_id: String,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub as_of: DateTime<Utc>,
    pub features: ScoreFeatures,
    /// The most significant realised outcome after `as_of`, when one exists.
    pub realised: Option<OutcomeKind>,
    /// Revenue attributed to the realised outcome, EUR (0 when none).
    pub realised_value_eur: f64,
}

/// A policy under validation. `decide` must be pure with respect to the case
/// (no clock, no database) so replay is deterministic.
pub trait Policy: Send + Sync + std::fmt::Debug {
    fn decide(&self, case: &ReplayCase) -> DecisionAction;

    /// Stable version string, used by [`PolicyRegistry`] and reports.
    fn version(&self) -> &str {
        "unversioned"
    }
}

/// What a rational actor, knowing the outcome, would have proposed at the
/// decision point. This is the agreement target.
pub fn realised_action_for(outcome: OutcomeKind) -> DecisionAction {
    match outcome {
        // A send happened (or paid off because of one): a contact was right.
        OutcomeKind::Delivered
        | OutcomeKind::Open
        | OutcomeKind::Click
        | OutcomeKind::Reply
        | OutcomeKind::Trial
        | OutcomeKind::PaidSubscription
        | OutcomeKind::RetainedMrr => DecisionAction::Contact,
        // The winning move was to ask for the meeting.
        OutcomeKind::PositiveReply | OutcomeKind::MeetingBooked | OutcomeKind::MeetingAttended => {
            DecisionAction::BookMeeting
        }
        // The address was bad: verify before sending.
        OutcomeKind::Bounce => DecisionAction::VerifyEmail,
        // Never contact again.
        OutcomeKind::Complaint | OutcomeKind::Unsubscribe => DecisionAction::StopPermanently,
    }
}

/// The replay result over a case set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    pub cases: i64,
    /// Cases where the policy proposed the action reality rewarded.
    pub agreements: i64,
    pub proposed_actions: BTreeMap<String, i64>,
    pub realised_actions: BTreeMap<String, i64>,
    /// Mean signed `(model EV − realised value)` over cases with a realised
    /// outcome, EUR. Positive = the model was optimistic; negative = it left
    /// value on the table. It is **signed**, not an absolute error.
    pub expected_value_error_eur: f64,
}

/// Run a policy over historical cases and compare with reality.
///
/// Pure: `scoring::score` is a pure function of the case's feature vector, so
/// the same cases and policy always produce the same result.
pub fn replay(cases: &[ReplayCase], policy: &dyn Policy) -> ReplayResult {
    let mut proposed: BTreeMap<String, i64> = BTreeMap::new();
    let mut realised: BTreeMap<String, i64> = BTreeMap::new();
    let mut agreements = 0i64;
    let mut ev_error_sum = 0.0f64;
    let mut ev_cases = 0i64;

    for case in cases {
        let action = policy.decide(case);
        *proposed.entry(action.as_str().to_string()).or_insert(0) += 1;

        if let Some(outcome) = case.realised {
            *realised.entry(outcome.as_str().to_string()).or_insert(0) += 1;
            if action == realised_action_for(outcome) {
                agreements += 1;
            }
            let model_ev = scoring::score(&case.features).expected_value_eur;
            ev_error_sum += model_ev - case.realised_value_eur;
            ev_cases += 1;
        }
    }

    ReplayResult {
        cases: cases.len() as i64,
        agreements,
        proposed_actions: proposed,
        realised_actions: realised,
        expected_value_error_eur: if ev_cases > 0 {
            ev_error_sum / ev_cases as f64
        } else {
            0.0
        },
    }
}

/// Champion/challenger shadow comparison over one case set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowComparison {
    pub champion: ReplayResult,
    pub challenger: ReplayResult,
    /// Cases the challenger agreed with reality on and the champion did not.
    pub challenger_wins: usize,
    /// Cases the champion agreed and the challenger did not.
    pub champion_wins: usize,
    /// Both agreed or both disagreed.
    pub ties: usize,
}

impl ShadowComparison {
    /// Cases with a realised outcome that the comparison covers.
    pub fn comparable_cases(&self) -> usize {
        self.challenger_wins + self.champion_wins + self.ties
    }

    /// Does the challenger strictly win?
    pub fn challenger_wins_overall(&self) -> bool {
        self.challenger_wins > self.champion_wins
    }
}

/// Run both policies over the same cases and count per-case wins.
pub fn shadow(
    champion: &dyn Policy,
    challenger: &dyn Policy,
    cases: &[ReplayCase],
) -> ShadowComparison {
    let champion_result = replay(cases, champion);
    let challenger_result = replay(cases, challenger);

    let mut challenger_wins = 0usize;
    let mut champion_wins = 0usize;
    let mut ties = 0usize;
    for case in cases {
        let Some(outcome) = case.realised else {
            continue;
        };
        let expected = realised_action_for(outcome);
        let champion_agrees = champion.decide(case) == expected;
        let challenger_agrees = challenger.decide(case) == expected;
        match (challenger_agrees, champion_agrees) {
            (true, false) => challenger_wins += 1,
            (false, true) => champion_wins += 1,
            _ => ties += 1,
        }
    }

    ShadowComparison {
        champion: champion_result,
        challenger: challenger_result,
        challenger_wins,
        champion_wins,
        ties,
    }
}

// ---------------------------------------------------------------------------
// Policy registry
// ---------------------------------------------------------------------------

/// Why a model version may not become production.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("policy version '{version}' is not registered for shadow evaluation")]
    NotShadowed { version: String },
    #[error(
        "policy version '{version}' has no completed shadow comparison; run one before staging"
    )]
    NoShadowComparison { version: String },
    #[error(
        "policy version '{version}' has {cases} shadow cases; at least {required} are required"
    )]
    InsufficientShadowCases {
        version: String,
        cases: usize,
        required: usize,
    },
    #[error("policy version '{version}' failed calibration: {reason}")]
    CalibrationRejected { version: String, reason: String },
    #[error(
        "policy version '{version}' has spent {days} days in shadow; at least {required} are required"
    )]
    InsufficientShadowDuration {
        version: String,
        days: i64,
        required: i64,
    },
    #[error(
        "policy version '{version}' was registered with a different policy instance; pass the \
         exact instance that was shadowed"
    )]
    PolicyMismatch { version: String },
}

#[derive(Debug)]
struct ShadowEntry {
    policy: Arc<dyn Policy>,
    staged_at: DateTime<Utc>,
    comparison: Option<ShadowComparison>,
    calibration: CalibrationReport,
}

/// Holds the production policy version and the versions under shadow.
///
/// A version only controls live outbound through [`Self::stage`], which
/// enforces all three gates. This makes "a new model version silently started
/// controlling outbound" impossible in-process.
pub struct PolicyRegistry {
    production_policy_version: Option<String>,
    shadow_policy_versions: BTreeMap<String, ShadowEntry>,
}

impl std::fmt::Debug for PolicyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyRegistry")
            .field("production_policy_version", &self.production_policy_version)
            .field(
                "shadow_policy_versions",
                &self.shadow_policy_versions.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for PolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self {
            production_policy_version: None,
            shadow_policy_versions: BTreeMap::new(),
        }
    }

    pub fn production_policy_version(&self) -> Option<&str> {
        self.production_policy_version.as_deref()
    }

    /// Versions currently in shadow.
    pub fn shadow_policy_versions(&self) -> Vec<String> {
        self.shadow_policy_versions.keys().cloned().collect()
    }

    /// Register a version for shadow evaluation. It cannot control production
    /// until [`Self::stage`] succeeds.
    pub fn register_shadow(
        &mut self,
        version: &str,
        policy: Arc<dyn Policy>,
        calibration: CalibrationReport,
        now: DateTime<Utc>,
    ) -> Result<(), GateError> {
        if version.trim().is_empty() {
            return Err(GateError::NotShadowed {
                version: version.to_string(),
            });
        }
        self.shadow_policy_versions.insert(
            version.to_string(),
            ShadowEntry {
                policy,
                staged_at: now,
                comparison: None,
                calibration,
            },
        );
        Ok(())
    }

    /// Attach the completed shadow comparison to a registered version.
    pub fn record_shadow_comparison(
        &mut self,
        version: &str,
        comparison: ShadowComparison,
    ) -> Result<(), GateError> {
        let entry = self
            .shadow_policy_versions
            .get_mut(version)
            .ok_or_else(|| GateError::NotShadowed {
                version: version.to_string(),
            })?;
        entry.comparison = Some(comparison);
        Ok(())
    }

    /// Promote a version to production, enforcing every gate.
    ///
    /// Refusals (each unit-tested):
    ///
    /// 1. the version is not in shadow, or has no completed comparison;
    /// 2. the comparison covers fewer than [`MIN_SHADOW_CASES`] cases;
    /// 3. calibration fails [`calibration::may_promote`] at
    ///    [`MIN_SHADOW_CALIBRATION_N`] / [`MAX_SHADOW_BRIER`];
    /// 4. fewer than [`MIN_DAYS_IN_SHADOW`] days have elapsed.
    pub fn stage(&mut self, version: &str, policy: Arc<dyn Policy>) -> Result<(), GateError> {
        // The caller must hold the exact instance that was shadowed: staging a
        // different object under a validated version would bypass the shadow
        // evidence entirely.
        let registered =
            self.shadow_policy_versions
                .get(version)
                .ok_or_else(|| GateError::NotShadowed {
                    version: version.to_string(),
                })?;
        if !std::ptr::eq(
            Arc::as_ptr(&registered.policy) as *const (),
            Arc::as_ptr(&policy) as *const (),
        ) {
            return Err(GateError::PolicyMismatch {
                version: version.to_string(),
            });
        }
        self.stage_at(version, Utc::now())
    }

    /// [`Self::stage`] with an explicit clock, for tests and replay.
    pub fn stage_at(&mut self, version: &str, now: DateTime<Utc>) -> Result<(), GateError> {
        let entry =
            self.shadow_policy_versions
                .get(version)
                .ok_or_else(|| GateError::NotShadowed {
                    version: version.to_string(),
                })?;

        let comparison =
            entry
                .comparison
                .as_ref()
                .ok_or_else(|| GateError::NoShadowComparison {
                    version: version.to_string(),
                })?;
        let cases = comparison.comparable_cases();
        if cases < MIN_SHADOW_CASES {
            return Err(GateError::InsufficientShadowCases {
                version: version.to_string(),
                cases,
                required: MIN_SHADOW_CASES,
            });
        }
        if !calibration::may_promote(
            &entry.calibration,
            MIN_SHADOW_CALIBRATION_N,
            MAX_SHADOW_BRIER,
        ) {
            return Err(GateError::CalibrationRejected {
                version: version.to_string(),
                reason: format!(
                    "n={}, brier={:.4} (max {MAX_SHADOW_BRIER}), overconfident={}",
                    entry.calibration.n,
                    entry.calibration.brier_score,
                    entry.calibration.overconfident
                ),
            });
        }
        let days = (now - entry.staged_at).num_days();
        if days < MIN_DAYS_IN_SHADOW {
            return Err(GateError::InsufficientShadowDuration {
                version: version.to_string(),
                days,
                required: MIN_DAYS_IN_SHADOW,
            });
        }

        self.production_policy_version = Some(version.to_string());
        self.shadow_policy_versions.remove(version);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Database loader
// ---------------------------------------------------------------------------

fn parse_eea_relevance(value: Option<&str>) -> EeaRelevance {
    match value
        .unwrap_or("unknown")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "in_scope" => EeaRelevance::InScope,
        "out_of_scope" => EeaRelevance::OutOfScope,
        _ => EeaRelevance::Unknown,
    }
}

fn parse_legal(value: Option<&str>) -> ContactDecision {
    match value
        .unwrap_or("approval_required")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "allowed" => ContactDecision::Allowed,
        "prohibited" => ContactDecision::Prohibited,
        // Unknown/unlisted verdicts fail closed to approval-required, exactly
        // like the legal policy module.
        _ => ContactDecision::ApprovalRequired,
    }
}

fn outcome_significance(kind: OutcomeKind) -> u8 {
    match kind {
        OutcomeKind::Delivered => 1,
        OutcomeKind::Open => 2,
        OutcomeKind::Click => 3,
        OutcomeKind::Reply => 4,
        OutcomeKind::Bounce => 5,
        OutcomeKind::Complaint => 6,
        OutcomeKind::Unsubscribe => 7,
        OutcomeKind::PositiveReply => 8,
        OutcomeKind::MeetingBooked => 9,
        OutcomeKind::MeetingAttended => 10,
        OutcomeKind::Trial => 11,
        OutcomeKind::PaidSubscription => 12,
        OutcomeKind::RetainedMrr => 13,
    }
}

/// Load historical replay cases for a tenant between two instants.
///
/// One case per `sales_decisions` row in the window (that is the canonical
/// record of a decision point). The feature vector is reconstructed from the
/// canonical tables **as of** the decision instant:
///
/// * account/contact firmographics and persona;
/// * `sales_signals` active at `as_of` (verified intent only — opens/clicks
///   are never intent);
/// * `sales_evidence` grounded before `as_of` (count, mean confidence, age);
/// * `sales_contact_points` verification for reachability;
/// * the latest `sales_contact_policy_decisions` verdict;
/// * `sales_outcomes` recorded up to `as_of` (risk/outcome features);
/// * open `sales_opportunities` amount as the expected LTV contribution;
/// * the **realised** outcome after `as_of` (the most significant one) and its
///   revenue, which is what the comparison is against.
///
/// `limit` is clamped to `[1, MAX_REPLAY_LIMIT]`.
pub async fn load_replay_cases(
    db: &PgPool,
    tenant_id: &str,
    window: (DateTime<Utc>, DateTime<Utc>),
    limit: i64,
) -> Result<Vec<ReplayCase>, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    let (start, end) = window;
    if end <= start {
        return Ok(Vec::new());
    }
    let limit = limit.clamp(1, MAX_REPLAY_LIMIT);

    let rows = sqlx::query(
        "SELECT d.id, d.created_at, d.account_id, d.contact_id, \
                a.icp_segment, a.country, a.industry, a.employees, a.eea_relevance, \
                c.persona, c.job_title, c.department, c.seniority, c.country AS contact_country, \
                c.language \
         FROM sales_decisions d \
         LEFT JOIN sales_accounts a ON a.id = d.account_id AND a.tenant_id = d.tenant_id \
         LEFT JOIN sales_contacts c ON c.id = d.contact_id AND c.tenant_id = d.tenant_id \
         WHERE d.tenant_id = $1 AND d.created_at >= $2 AND d.created_at < $3 \
           AND d.account_id IS NOT NULL \
         ORDER BY d.created_at ASC \
         LIMIT $4",
    )
    .bind(tenant_id)
    .bind(start)
    .bind(end)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let mut cases = Vec::with_capacity(rows.len());
    for row in rows {
        let as_of: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let account_id: Uuid = row
            .try_get("account_id")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let contact_id: Option<Uuid> = row
            .try_get("contact_id")
            .map_err(|error| SalesError::Database(error.to_string()))?;

        let mut features = ScoreFeatures {
            now: as_of,
            ..ScoreFeatures::default()
        };
        let icp_segment: Option<String> = row
            .try_get("icp_segment")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        // Documented coarse mapping: a non-empty ICP segment is a partial
        // match (the caller's ICP definition is not stored per account),
        // unknown otherwise.
        features.segment_match = if icp_segment
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            SegmentMatch::Partial
        } else {
            SegmentMatch::Unknown
        };
        features.industry = row
            .try_get("industry")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        features.employees = row
            .try_get::<Option<i32>, _>("employees")
            .map_err(|error| SalesError::Database(error.to_string()))?
            .map(i64::from);
        let eea: Option<String> = row
            .try_get("eea_relevance")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        features.eea_relevance = parse_eea_relevance(eea.as_deref());
        features.persona.job_title = row
            .try_get("job_title")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        features.persona.department = row
            .try_get("department")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        features.persona.seniority = row
            .try_get("seniority")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        features.email_stack = EmailStackFeatures::default();

        features.intent_signals = load_signals(db, tenant_id, account_id, as_of).await?;
        features.evidence = load_evidence_features(db, tenant_id, account_id, as_of).await?;
        if let Some(contact_id) = contact_id {
            features.reachability = load_reachability(db, tenant_id, contact_id).await?;
            features.legal = load_legal(db, tenant_id, contact_id).await?;
        }
        let (outcomes, risk) =
            load_prior_outcomes(db, tenant_id, account_id, contact_id, as_of).await?;
        features.outcomes = outcomes;
        features.risk = risk;
        features.economics.expected_ltv_contribution_eur =
            load_open_pipeline_eur(db, tenant_id, account_id).await?;
        features.economics.outreach_cost_eur = DEFAULT_OUTREACH_COST_EUR;

        let (realised, realised_value_eur) =
            load_realised_outcome(db, tenant_id, account_id, contact_id, as_of, end).await?;

        cases.push(ReplayCase {
            tenant_id: tenant_id.to_string(),
            account_id: Some(account_id),
            contact_id,
            as_of,
            features,
            realised,
            realised_value_eur,
        });
    }
    Ok(cases)
}

async fn load_signals(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    as_of: DateTime<Utc>,
) -> Result<Vec<SignalObservation>, SalesError> {
    let rows = sqlx::query(
        "SELECT signal_type, strength, observed_at FROM sales_signals \
         WHERE tenant_id = $1 AND account_id = $2 AND observed_at <= $3 \
           AND (expires_at IS NULL OR expires_at > $3) \
         ORDER BY observed_at DESC",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(as_of)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    rows.into_iter()
        .map(|row| {
            Ok(SignalObservation {
                signal_type: row
                    .try_get("signal_type")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                strength: row
                    .try_get::<f64, _>("strength")
                    .map_err(|error| SalesError::Database(error.to_string()))?
                    as f32,
                observed_at: row
                    .try_get("observed_at")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
            })
        })
        .collect()
}

async fn load_evidence_features(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    as_of: DateTime<Utc>,
) -> Result<EvidenceFeatures, SalesError> {
    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count, COALESCE(AVG(confidence), 0)::float8 AS mean_confidence, \
                MAX(observed_at) AS newest \
         FROM sales_evidence \
         WHERE tenant_id = $1 AND account_id = $2 AND observed_at <= $3",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(as_of)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let count: i64 = row
        .try_get("count")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let mean_confidence: f64 = row
        .try_get("mean_confidence")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let newest: Option<DateTime<Utc>> = row
        .try_get("newest")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(EvidenceFeatures {
        count: count.max(0) as u32,
        mean_confidence: mean_confidence.clamp(0.0, 1.0) as f32,
        newest_age_days: newest
            .map(|newest| (as_of - newest).num_seconds() as f32 / 86_400.0)
            .filter(|age| age.is_finite() && *age >= 0.0),
    })
}

async fn load_reachability(
    db: &PgPool,
    tenant_id: &str,
    contact_id: Uuid,
) -> Result<ReachabilityFeatures, SalesError> {
    let row = sqlx::query(
        "SELECT COUNT(*) FILTER (WHERE verification = 'valid')::bigint AS verified, \
                COALESCE(MAX(confidence), 0)::float8 AS best_confidence \
         FROM sales_contact_points WHERE tenant_id = $1 AND contact_id = $2",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let verified: i64 = row
        .try_get("verified")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let best_confidence: f64 = row
        .try_get("best_confidence")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(ReachabilityFeatures {
        verified_contact_points: verified.max(0) as u32,
        best_confidence: best_confidence.clamp(0.0, 1.0) as f32,
    })
}

async fn load_legal(
    db: &PgPool,
    tenant_id: &str,
    contact_id: Uuid,
) -> Result<ContactDecision, SalesError> {
    let decision: Option<String> = sqlx::query_scalar(
        "SELECT decision FROM sales_contact_policy_decisions \
         WHERE tenant_id = $1 AND contact_id = $2 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(parse_legal(decision.as_deref()))
}

async fn load_prior_outcomes(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    contact_id: Option<Uuid>,
    as_of: DateTime<Utc>,
) -> Result<(OutcomeFeatures, RiskFeatures), SalesError> {
    let rows = sqlx::query(
        "SELECT outcome, COUNT(*)::bigint AS count FROM sales_outcomes \
         WHERE tenant_id = $1 AND account_id = $2 \
           AND ($3::uuid IS NULL OR contact_id IS NULL OR contact_id = $3) \
           AND occurred_at <= $4 \
         GROUP BY outcome",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(contact_id)
    .bind(as_of)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let mut outcomes = OutcomeFeatures::default();
    let mut risk = RiskFeatures::default();
    for row in rows {
        let kind: String = row
            .try_get("outcome")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let count = count.max(0) as u32;
        match OutcomeKind::parse(&kind) {
            Some(OutcomeKind::Delivered) => outcomes.delivered = count,
            Some(OutcomeKind::Open) => outcomes.opens = count,
            Some(OutcomeKind::Click) => outcomes.clicks = count,
            Some(OutcomeKind::Reply) => outcomes.replies = count,
            Some(OutcomeKind::PositiveReply) => outcomes.positive_replies = count,
            Some(OutcomeKind::MeetingBooked) => outcomes.meetings_booked = count,
            Some(OutcomeKind::MeetingAttended) => outcomes.meetings_booked = count,
            Some(OutcomeKind::Trial) => outcomes.trials = count,
            Some(OutcomeKind::PaidSubscription) => outcomes.paid_subscriptions = count,
            Some(OutcomeKind::RetainedMrr) => outcomes.paid_subscriptions = count,
            Some(OutcomeKind::Bounce) => outcomes.bounces = count,
            Some(OutcomeKind::Complaint) => {
                outcomes.complaints = count;
                risk.complaints = count;
            }
            Some(OutcomeKind::Unsubscribe) => {
                outcomes.unsubscribes = count;
                risk.negative_replies = risk.negative_replies.saturating_add(count);
            }
            None => {}
        }
    }
    Ok((outcomes, risk))
}

async fn load_open_pipeline_eur(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<f64, SalesError> {
    let amount: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_eur), 0)::float8 FROM sales_opportunities \
         WHERE tenant_id = $1 AND account_id = $2 \
           AND stage IN ('open', 'qualified', 'negotiation')",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(if amount.is_finite() && amount > 0.0 {
        amount
    } else {
        0.0
    })
}

async fn load_realised_outcome(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    contact_id: Option<Uuid>,
    as_of: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Result<(Option<OutcomeKind>, f64), SalesError> {
    let rows = sqlx::query(
        "SELECT outcome, COUNT(*)::bigint AS count, \
                COALESCE(SUM(value_eur) FILTER (WHERE outcome IN \
                    ('trial', 'paid_subscription', 'retained_mrr')), 0)::float8 AS revenue \
         FROM sales_outcomes \
         WHERE tenant_id = $1 AND account_id = $2 \
           AND ($3::uuid IS NULL OR contact_id IS NULL OR contact_id = $3) \
           AND occurred_at > $4 AND occurred_at < $5 \
         GROUP BY outcome",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(contact_id)
    .bind(as_of)
    .bind(window_end)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let mut best: Option<(u8, OutcomeKind)> = None;
    let mut revenue = 0.0f64;
    for row in rows {
        let kind: String = row
            .try_get("outcome")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let value: f64 = row
            .try_get("revenue")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        if value.is_finite() && value > 0.0 {
            revenue += value;
        }
        let Some(kind) = OutcomeKind::parse(&kind) else {
            continue;
        };
        let rank = outcome_significance(kind);
        if best.map(|(best_rank, _)| rank > best_rank).unwrap_or(true) {
            best = Some((rank, kind));
        }
    }
    Ok((best.map(|(_, kind)| kind), revenue))
}

/// A convenience window helper for the common "last N days" case.
pub fn last_days(days: i64) -> (DateTime<Utc>, DateTime<Utc>) {
    let end = Utc::now();
    (end - Duration::days(days.max(0)), end)
}

/// Convenience used by reports: the number of `(action, count)` pairs.
pub fn action_histogram(
    actions: impl IntoIterator<Item = DecisionAction>,
) -> BTreeMap<String, i64> {
    action_counts(actions)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::calibration;

    #[derive(Debug)]
    struct FixedPolicy {
        version: &'static str,
        action: DecisionAction,
    }

    impl Policy for FixedPolicy {
        fn decide(&self, _case: &ReplayCase) -> DecisionAction {
            self.action
        }

        fn version(&self) -> &str {
            self.version
        }
    }

    #[derive(Debug)]
    struct OutcomePolicy;

    impl Policy for OutcomePolicy {
        fn decide(&self, case: &ReplayCase) -> DecisionAction {
            match case.realised {
                Some(outcome) => realised_action_for(outcome),
                None => DecisionAction::DoNothing,
            }
        }
    }

    fn case_with(realised: Option<OutcomeKind>, realised_value_eur: f64, ltv: f64) -> ReplayCase {
        let mut features = ScoreFeatures::default();
        features.economics.expected_ltv_contribution_eur = ltv;
        features.legal = ContactDecision::Allowed;
        ReplayCase {
            tenant_id: "tenant-a".into(),
            account_id: Some(Uuid::new_v4()),
            contact_id: Some(Uuid::new_v4()),
            as_of: Utc::now() - Duration::days(30),
            features,
            realised,
            realised_value_eur,
        }
    }

    fn passing_calibration() -> CalibrationReport {
        // 100 observations, constant p=0.7, exactly 70 realised: a perfectly
        // calibrated report with Brier 0.21.
        let observations: Vec<(f64, bool)> = (0..100).map(|index| (0.7, index < 70)).collect();
        calibration(&observations)
    }

    fn good_comparison(cases: usize) -> ShadowComparison {
        ShadowComparison {
            champion: ReplayResult {
                cases: cases as i64,
                agreements: 0,
                proposed_actions: BTreeMap::new(),
                realised_actions: BTreeMap::new(),
                expected_value_error_eur: 0.0,
            },
            challenger: ReplayResult {
                cases: cases as i64,
                agreements: cases as i64,
                proposed_actions: BTreeMap::new(),
                realised_actions: BTreeMap::new(),
                expected_value_error_eur: 0.0,
            },
            challenger_wins: cases,
            champion_wins: 0,
            ties: 0,
        }
    }

    // -- replay -------------------------------------------------------------

    #[test]
    fn replay_agreement_and_disagreement_against_reality() {
        let cases = vec![
            case_with(Some(OutcomeKind::PaidSubscription), 500.0, 1_000.0),
            case_with(Some(OutcomeKind::Complaint), 0.0, 1_000.0),
        ];
        // Reality rewarded Contact for the paid subscription and
        // StopPermanently for the complaint.
        #[derive(Debug)]
        struct MixedPolicy;
        impl Policy for MixedPolicy {
            fn decide(&self, case: &ReplayCase) -> DecisionAction {
                match case.realised {
                    Some(OutcomeKind::PaidSubscription) => DecisionAction::Contact,
                    _ => DecisionAction::Contact, // wrong for the complaint
                }
            }
        }
        let result = replay(&cases, &MixedPolicy);
        assert_eq!(result.cases, 2);
        assert_eq!(result.agreements, 1);
        assert_eq!(result.realised_actions.get("paid_subscription"), Some(&1));
        assert_eq!(result.realised_actions.get("complaint"), Some(&1));
        assert_eq!(result.proposed_actions.get("contact"), Some(&2));

        let perfect = replay(&cases, &OutcomePolicy);
        assert_eq!(perfect.agreements, 2, "a policy that knows reality agrees");
    }

    #[test]
    fn expected_value_error_is_signed_not_absolute() {
        // Model EV positive, no revenue realised → positive (optimistic) error.
        let optimistic = vec![case_with(Some(OutcomeKind::Reply), 0.0, 1_000.0)];
        let result = replay(
            &optimistic,
            &FixedPolicy {
                version: "v",
                action: DecisionAction::Contact,
            },
        );
        assert!(
            result.expected_value_error_eur > 0.0,
            "optimistic error must be positive: {}",
            result.expected_value_error_eur
        );

        // Model EV tiny, huge revenue realised → negative error.
        let pessimistic = vec![case_with(
            Some(OutcomeKind::PaidSubscription),
            100_000.0,
            1.0,
        )];
        let result = replay(
            &pessimistic,
            &FixedPolicy {
                version: "v",
                action: DecisionAction::Contact,
            },
        );
        assert!(
            result.expected_value_error_eur < 0.0,
            "pessimistic error must be negative: {}",
            result.expected_value_error_eur
        );
    }

    #[test]
    fn cases_without_a_realised_outcome_do_not_count_as_agreements() {
        let cases = vec![case_with(None, 0.0, 1_000.0)];
        let result = replay(&cases, &OutcomePolicy);
        assert_eq!(result.cases, 1);
        assert_eq!(result.agreements, 0);
        assert_eq!(result.expected_value_error_eur, 0.0);
    }

    #[test]
    fn every_outcome_maps_to_a_documented_action() {
        let expected = [
            (OutcomeKind::Delivered, DecisionAction::Contact),
            (OutcomeKind::Open, DecisionAction::Contact),
            (OutcomeKind::Click, DecisionAction::Contact),
            (OutcomeKind::Reply, DecisionAction::Contact),
            (OutcomeKind::PositiveReply, DecisionAction::BookMeeting),
            (OutcomeKind::MeetingBooked, DecisionAction::BookMeeting),
            (OutcomeKind::MeetingAttended, DecisionAction::BookMeeting),
            (OutcomeKind::Trial, DecisionAction::Contact),
            (OutcomeKind::PaidSubscription, DecisionAction::Contact),
            (OutcomeKind::RetainedMrr, DecisionAction::Contact),
            (OutcomeKind::Bounce, DecisionAction::VerifyEmail),
            (OutcomeKind::Complaint, DecisionAction::StopPermanently),
            (OutcomeKind::Unsubscribe, DecisionAction::StopPermanently),
        ];
        for (outcome, action) in expected {
            assert_eq!(realised_action_for(outcome), action, "{outcome}");
        }
    }

    // -- shadow -------------------------------------------------------------

    #[test]
    fn shadow_counts_per_case_wins_and_ties() {
        let cases = vec![
            case_with(Some(OutcomeKind::PaidSubscription), 500.0, 1_000.0),
            case_with(Some(OutcomeKind::Complaint), 0.0, 1_000.0),
            case_with(Some(OutcomeKind::Reply), 0.0, 1_000.0),
        ];
        // Champion always contacts: agrees on paid/reply, disagrees on complaint.
        let champion = FixedPolicy {
            version: "champion",
            action: DecisionAction::Contact,
        };
        // Challenger always stops: agrees on complaint, disagrees elsewhere.
        let challenger = FixedPolicy {
            version: "challenger",
            action: DecisionAction::StopPermanently,
        };
        let comparison = shadow(&champion, &challenger, &cases);
        assert_eq!(comparison.comparable_cases(), 3);
        assert_eq!(comparison.champion_wins, 2);
        assert_eq!(comparison.challenger_wins, 1);
        assert_eq!(comparison.ties, 0);
        assert!(!comparison.challenger_wins_overall());
        assert_eq!(comparison.champion.agreements, 2);
        assert_eq!(comparison.challenger.agreements, 1);
    }

    // -- policy registry ----------------------------------------------------

    #[test]
    fn staging_refuses_a_version_with_too_few_shadow_cases() {
        let mut registry = PolicyRegistry::new();
        let policy: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v2",
            action: DecisionAction::Contact,
        });
        registry
            .register_shadow(
                "v2",
                policy.clone(),
                passing_calibration(),
                Utc::now() - Duration::days(30),
            )
            .unwrap();
        registry
            .record_shadow_comparison("v2", good_comparison(MIN_SHADOW_CASES - 1))
            .unwrap();
        let error = registry.stage("v2", policy).expect_err("too few cases");
        assert!(matches!(
            error,
            GateError::InsufficientShadowCases {
                cases,
                required,
                ..
            } if cases == MIN_SHADOW_CASES - 1 && required == MIN_SHADOW_CASES
        ));
        assert_eq!(registry.production_policy_version(), None);
    }

    #[test]
    fn staging_refuses_a_badly_calibrated_version() {
        let mut registry = PolicyRegistry::new();
        let policy: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v2",
            action: DecisionAction::Contact,
        });
        let overconfident: Vec<(f64, bool)> = (0..100).map(|index| (0.95, index < 50)).collect();
        registry
            .register_shadow(
                "v2",
                policy.clone(),
                calibration(&overconfident),
                Utc::now() - Duration::days(30),
            )
            .unwrap();
        registry
            .record_shadow_comparison("v2", good_comparison(MIN_SHADOW_CASES))
            .unwrap();
        let error = registry.stage("v2", policy).expect_err("bad calibration");
        assert!(matches!(error, GateError::CalibrationRejected { .. }));
        assert_eq!(registry.production_policy_version(), None);
    }

    #[test]
    fn staging_refuses_a_version_with_too_few_days_in_shadow() {
        let mut registry = PolicyRegistry::new();
        let policy: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v2",
            action: DecisionAction::Contact,
        });
        let staged_at = Utc::now() - Duration::days(MIN_DAYS_IN_SHADOW - 1);
        registry
            .register_shadow("v2", policy.clone(), passing_calibration(), staged_at)
            .unwrap();
        registry
            .record_shadow_comparison("v2", good_comparison(MIN_SHADOW_CASES))
            .unwrap();
        let error = registry
            .stage_at("v2", Utc::now())
            .expect_err("too few days");
        assert!(matches!(
            error,
            GateError::InsufficientShadowDuration { days, required, .. }
                if days < required
        ));
        assert_eq!(registry.production_policy_version(), None);
    }

    #[test]
    fn staging_refuses_an_unregistered_version() {
        let mut registry = PolicyRegistry::new();
        let policy: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v2",
            action: DecisionAction::Contact,
        });
        assert!(matches!(
            registry.stage("v2", policy),
            Err(GateError::NotShadowed { .. })
        ));
    }

    #[test]
    fn staging_refuses_a_different_policy_instance() {
        let mut registry = PolicyRegistry::new();
        let registered: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v2",
            action: DecisionAction::Contact,
        });
        let impostor: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v2",
            action: DecisionAction::Contact,
        });
        registry
            .register_shadow(
                "v2",
                registered,
                passing_calibration(),
                Utc::now() - Duration::days(30),
            )
            .unwrap();
        registry
            .record_shadow_comparison("v2", good_comparison(MIN_SHADOW_CASES + 1))
            .unwrap();
        assert!(matches!(
            registry.stage("v2", impostor),
            Err(GateError::PolicyMismatch { .. })
        ));
        assert_eq!(registry.production_policy_version(), None);
    }

    #[test]
    fn staging_refuses_without_a_completed_comparison() {
        let mut registry = PolicyRegistry::new();
        let policy: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v2",
            action: DecisionAction::Contact,
        });
        registry
            .register_shadow(
                "v2",
                policy.clone(),
                passing_calibration(),
                Utc::now() - Duration::days(30),
            )
            .unwrap();
        assert!(matches!(
            registry.stage("v2", policy),
            Err(GateError::NoShadowComparison { .. })
        ));
    }

    #[test]
    fn staging_succeeds_when_all_three_gates_pass() {
        let mut registry = PolicyRegistry::new();
        let policy: Arc<dyn Policy> = Arc::new(FixedPolicy {
            version: "v3",
            action: DecisionAction::Contact,
        });
        let staged_at = Utc::now() - Duration::days(MIN_DAYS_IN_SHADOW);
        registry
            .register_shadow("v3", policy.clone(), passing_calibration(), staged_at)
            .unwrap();
        registry
            .record_shadow_comparison("v3", good_comparison(MIN_SHADOW_CASES + 10))
            .unwrap();
        registry.stage("v3", policy).expect("all gates pass");
        assert_eq!(registry.production_policy_version(), Some("v3"));
        assert!(registry.shadow_policy_versions().is_empty());
    }

    #[test]
    fn last_days_window_is_ordered_and_non_negative() {
        let (start, end) = last_days(7);
        assert!(start < end);
        let (same, _) = last_days(-1);
        let (end_now, end_now_2) = (Utc::now(), Utc::now());
        assert!(same <= end_now && end_now <= end_now_2);
    }

    #[test]
    fn action_histogram_groups_wire_names() {
        let histogram = action_histogram([DecisionAction::Wait, DecisionAction::Wait]);
        assert_eq!(histogram.get("wait"), Some(&2));
    }
}
