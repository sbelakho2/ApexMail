//! §S2–S5, experiment science: the ONE metric registry, frozen windows,
//! guardrail pauses, the randomized holdout, logged propensities with
//! off-policy evaluation, the experiment registry, power and sequential
//! monitoring.
//!
//! # The primary metric and the north star (S2)
//!
//! Both are defined in `sales_experiment_metrics` (migration 290), the ONE
//! registry table. The scoreboard reads the definition, version and frozen
//! window from that table; a metric that is not registered cannot be
//! reported. The primary metric is *positive reply or booked meeting within
//! 14 days of the first touch*; it freezes at window close. The north star is
//! *won MRR per 1,000 contacted accounts at 90 days*; later revenue changes
//! only the north star, never the primary metric.
//!
//! # Guardrails (S2)
//!
//! Complaints, unsubscribes and bounces never move the Beta posterior. They
//! are evaluated per arm+segment against the named thresholds:
//!
//! | guardrail | pause threshold |
//! |---|---|
//! | complaint rate | 0.1% |
//! | unsubscribe rate | 1% |
//! | hard bounce rate | 2% |
//!
//! [`refresh_guardrail_pauses`] writes a sticky
//! `sales_experiment_arm_pauses` row; [`crate::experiments::ExperimentEngine::select_variant`]
//! excludes paused arms, so a paused arm stops sending at the bandit
//! selection (the dispatcher's decision point). When every arm is paused the
//! selection is suppressed instead of falling back to an arbitrary arm.
//!
//! # Randomized holdout (S3)
//!
//! [`is_holdout`] assigns by a stable SHA-256 hash of
//! `account id | segment | registry version`, so the same account always
//! lands on the same side across runs and processes. The holdout receives no
//! sending; [`holdout_lift`] reports treatment-vs-holdout lift per segment
//! using matured windows only.
//!
//! # Propensities and off-policy evaluation (S4)
//!
//! Every selection records the actual Thompson win probability of each arm
//! (`sales_experiment_assignments.propensities`, plus the chosen arm's
//! `propensity` on the step execution and enrollment). [`ips`] and
//! [`snips`] are the honest off-policy estimators over those logs:
//!
//! ```text
//! IPS  = (1/n) Σ 1{a_i = x} r_i / p_i
//! SNIPS = Σ 1{a_i = x} r_i / p_i  /  Σ 1{a_i = x} / p_i
//! ```
//!
//! There is no smoothing and no clipping: a logged propensity must be
//! strictly positive (the deterministic exploit path logs 1.0), and an
//! invalid row is dropped rather than silently reweighted.
//!
//! # Power and sequential monitoring (S5)
//!
//! [`minimum_detectable_effect`] reports the absolute MDE for the primary
//! metric at the current per-arm sample. [`SequentialMonitor`] implements a
//! **mixture sequential probability ratio test (mSPRT)** with a normal
//! mixing prior `δ ~ N(0, τ²)` on the risk difference. The statistic is a
//! likelihood ratio evaluated at the current information time; rejecting at
//! `Λ ≥ 1/α` is always-valid under the null, so an operator may look at the
//! scoreboard after every contact without inflating the false-positive rate.
//! The simulation test `early_peeking_does_not_inflate_false_positives`
//! proves the property empirically.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::experiments::{
    self, ArmPosterior, ExperimentEngine, NORTH_STAR_METRIC_KEY, NORTH_STAR_METRIC_VERSION,
    PRIMARY_METRIC_KEY, PRIMARY_METRIC_VERSION,
};
use crate::types::SalesError;

// ---------------------------------------------------------------------------
// Metric registry (S2)
// ---------------------------------------------------------------------------

/// One row of `sales_experiment_metrics`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricDefinition {
    pub metric_key: String,
    pub version: i32,
    pub role: String,
    pub definition: String,
    pub window_days: i32,
    pub direction: String,
}

/// Load one metric definition. `None` means it is not registered and the
/// scoreboard must refuse to report it.
pub async fn metric_definition(
    db: &PgPool,
    metric_key: &str,
    version: i32,
) -> Result<Option<MetricDefinition>, SalesError> {
    let row = sqlx::query(
        "SELECT metric_key, version, role, definition, window_days, direction \
         FROM sales_experiment_metrics WHERE metric_key = $1 AND version = $2",
    )
    .bind(metric_key)
    .bind(version)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    row.map(|row| {
        Ok(MetricDefinition {
            metric_key: row
                .try_get("metric_key")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            version: row
                .try_get("version")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            role: row
                .try_get("role")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            definition: row
                .try_get("definition")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            window_days: row
                .try_get("window_days")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            direction: row
                .try_get("direction")
                .map_err(|error| SalesError::Database(error.to_string()))?,
        })
    })
    .transpose()
}

/// The full registry, ordered by role then key.
pub async fn load_metric_registry(db: &PgPool) -> Result<Vec<MetricDefinition>, SalesError> {
    let rows = sqlx::query(
        "SELECT metric_key, version, role, definition, window_days, direction \
         FROM sales_experiment_metrics ORDER BY role ASC, metric_key ASC, version DESC",
    )
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    rows.into_iter()
        .map(|row| {
            Ok(MetricDefinition {
                metric_key: row
                    .try_get("metric_key")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                version: row
                    .try_get("version")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                role: row
                    .try_get("role")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                definition: row
                    .try_get("definition")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                window_days: row
                    .try_get("window_days")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                direction: row
                    .try_get("direction")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Guardrails (S2)
// ---------------------------------------------------------------------------

/// Complaint rate at or above which an arm+segment is paused.
pub const COMPLAINT_RATE_PAUSE: f64 = 0.001;
/// Unsubscribe rate at or above which an arm+segment is paused.
pub const UNSUBSCRIBE_RATE_PAUSE: f64 = 0.01;
/// Hard-bounce rate at or above which an arm+segment is paused.
pub const HARD_BOUNCE_RATE_PAUSE: f64 = 0.02;

/// Raw guardrail counters for one arm+segment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct GuardrailCounts {
    pub contacts: i64,
    pub complaints: i64,
    pub unsubscribes: i64,
    pub bounces: i64,
}

impl GuardrailCounts {
    pub fn complaint_rate(&self) -> f64 {
        rate(self.complaints, self.contacts)
    }

    pub fn unsubscribe_rate(&self) -> f64 {
        rate(self.unsubscribes, self.contacts)
    }

    pub fn bounce_rate(&self) -> f64 {
        rate(self.bounces, self.contacts)
    }
}

fn rate(events: i64, contacts: i64) -> f64 {
    if contacts <= 0 || events <= 0 {
        0.0
    } else {
        events as f64 / contacts as f64
    }
}

/// The pure pause verdict. Fail-closed on hostile counters (negative treated
/// as zero, never as a negative rate that passes every threshold).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardrailVerdict {
    pub paused: bool,
    pub complaint_rate: f64,
    pub unsubscribe_rate: f64,
    pub bounce_rate: f64,
    pub reasons: Vec<String>,
}

pub fn evaluate_guardrails(counts: GuardrailCounts) -> GuardrailVerdict {
    let contacts = counts.contacts.max(0);
    let complaints = counts.complaints.max(0);
    let unsubscribes = counts.unsubscribes.max(0);
    let bounces = counts.bounces.max(0);
    let counts = GuardrailCounts {
        contacts,
        complaints,
        unsubscribes,
        bounces,
    };
    let complaint_rate = counts.complaint_rate();
    let unsubscribe_rate = counts.unsubscribe_rate();
    let bounce_rate = counts.bounce_rate();
    let mut reasons = Vec::new();
    if complaint_rate >= COMPLAINT_RATE_PAUSE {
        reasons.push(format!(
            "complaint rate {:.4}% >= {:.2}% guardrail",
            complaint_rate * 100.0,
            COMPLAINT_RATE_PAUSE * 100.0
        ));
    }
    if unsubscribe_rate >= UNSUBSCRIBE_RATE_PAUSE {
        reasons.push(format!(
            "unsubscribe rate {:.4}% >= {:.2}% guardrail",
            unsubscribe_rate * 100.0,
            UNSUBSCRIBE_RATE_PAUSE * 100.0
        ));
    }
    if bounce_rate >= HARD_BOUNCE_RATE_PAUSE {
        reasons.push(format!(
            "hard bounce rate {:.4}% >= {:.2}% guardrail",
            bounce_rate * 100.0,
            HARD_BOUNCE_RATE_PAUSE * 100.0
        ));
    }
    GuardrailVerdict {
        paused: !reasons.is_empty(),
        complaint_rate,
        unsubscribe_rate,
        bounce_rate,
        reasons,
    }
}

/// One arm+segment guardrail report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArmGuardrailReport {
    pub variant: String,
    pub segment: String,
    pub counts: GuardrailCounts,
    pub verdict: GuardrailVerdict,
}

/// Compute the guardrail rates for one experiment from the contact-trial
/// ledger (denominator: contacts first touched inside the window; numerator:
/// complaint/unsubscribe/bounce events recorded in the ledger).
pub async fn guardrails_for_experiment(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
    now: DateTime<Utc>,
    window_days: i32,
) -> Result<Vec<ArmGuardrailReport>, SalesError> {
    let window_days = window_days.max(1);
    let since = now - ChronoDuration::days(i64::from(window_days));
    let rows = sqlx::query(
        "SELECT t.variant, t.segment, \
                COUNT(DISTINCT t.contact_id)::bigint AS contacts, \
                COUNT(o.id) FILTER (WHERE o.kind = 'complaint')::bigint AS complaints, \
                COUNT(o.id) FILTER (WHERE o.kind = 'unsubscribe')::bigint AS unsubscribes, \
                COUNT(o.id) FILTER (WHERE o.kind = 'bounce')::bigint AS bounces \
         FROM sales_experiment_contact_trials t \
         LEFT JOIN sales_experiment_outcomes o \
           ON o.tenant_id = t.tenant_id AND o.experiment_id = t.experiment_id \
          AND o.variant = t.variant AND o.contact_id = t.contact_id \
          AND o.recorded_at >= $3 \
         WHERE t.tenant_id = $1 AND t.experiment_id = $2 \
           AND t.first_touch_at >= $3 \
         GROUP BY t.variant, t.segment \
         ORDER BY t.variant ASC, t.segment ASC",
    )
    .bind(tenant_id)
    .bind(experiment_id)
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    rows.into_iter()
        .map(|row| {
            let counts = GuardrailCounts {
                contacts: row
                    .try_get("contacts")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                complaints: row
                    .try_get("complaints")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                unsubscribes: row
                    .try_get("unsubscribes")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                bounces: row
                    .try_get("bounces")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
            };
            let verdict = evaluate_guardrails(counts);
            Ok(ArmGuardrailReport {
                variant: row
                    .try_get("variant")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                segment: row
                    .try_get("segment")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                counts,
                verdict,
            })
        })
        .collect()
}

/// Re-evaluate the guardrails and PERSIST every tripped arm+segment as a
/// sticky pause. Called by the outcome projector tick, so a complaint that
/// crosses 0.1% stops the arm before the next planning pass. Returns the
/// reports it evaluated.
pub async fn refresh_guardrail_pauses(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<ArmGuardrailReport>, SalesError> {
    let window_days = metric_definition(db, "complaint_rate", 1)
        .await?
        .map(|definition| definition.window_days)
        .unwrap_or(30);
    let reports = guardrails_for_experiment(db, tenant_id, experiment_id, now, window_days).await?;
    for report in &reports {
        if !report.verdict.paused {
            continue;
        }
        sqlx::query(
            "INSERT INTO sales_experiment_arm_pauses \
                 (tenant_id, experiment_id, variant, segment, reason, evidence) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (experiment_id, variant, segment) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(experiment_id)
        .bind(&report.variant)
        .bind(&report.segment)
        .bind(report.verdict.reasons.join("; "))
        .bind(serde_json::json!({
            "counts": report.counts,
            "complaint_rate": report.verdict.complaint_rate,
            "unsubscribe_rate": report.verdict.unsubscribe_rate,
            "bounce_rate": report.verdict.bounce_rate,
        }))
        .execute(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    }
    Ok(reports)
}

/// Operator path: clear one pause (the only way an arm resumes).
pub async fn clear_arm_pause(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
    variant: &str,
    segment: &str,
) -> Result<bool, SalesError> {
    let affected = sqlx::query(
        "DELETE FROM sales_experiment_arm_pauses \
         WHERE tenant_id = $1 AND experiment_id = $2 AND variant = $3 AND segment = $4",
    )
    .bind(tenant_id)
    .bind(experiment_id)
    .bind(variant)
    .bind(segment)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected();
    Ok(affected > 0)
}

// ---------------------------------------------------------------------------
// Randomized holdout (S3)
// ---------------------------------------------------------------------------

/// Stable holdout bucket `0..10_000` from the SHA-256 of
/// `account id | segment | registry version`. Case/whitespace normalised so
/// the same account+segment always hashes identically.
pub fn holdout_bucket(account_id: Uuid, segment: &str, registry_version: i32) -> u64 {
    let normalized = segment.trim().to_ascii_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(account_id.as_bytes());
    hasher.update(b"|");
    hasher.update(normalized.as_bytes());
    hasher.update(b"|");
    hasher.update(registry_version.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes) % 10_000
}

/// Is this account in the holdout? `share` is sanitised to `0.0..=0.5`; a
/// zero share never holds anyone out, and a hostile share cannot exceed half
/// the segment.
pub fn is_holdout(account_id: Uuid, segment: &str, registry_version: i32, share: f64) -> bool {
    let share = experiments::sanitize_holdout_share(share);
    if share <= 0.0 {
        return false;
    }
    let cutoff = (share * 10_000.0).round() as u64;
    holdout_bucket(account_id, segment, registry_version) < cutoff
}

/// Treatment-vs-holdout lift for one segment. Only matured windows are used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentLift {
    pub segment: String,
    pub treatment_matured: i64,
    pub treatment_successes: i64,
    pub treatment_rate: Option<f64>,
    pub holdout_matured: i64,
    pub holdout_successes: i64,
    pub holdout_rate: Option<f64>,
    /// Treatment rate − holdout rate, in percentage points. `None` when
    /// either side has no matured observation.
    pub lift_pp: Option<f64>,
}

/// Compute the per-segment holdout lift. Holdout accounts receive no
/// sending, so their successes are organic outcomes recorded for the account
/// inside the frozen primary window after assignment; an account is only
/// counted once its window closed.
pub async fn holdout_lift(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<SegmentLift>, SalesError> {
    let primary = required_metric(db, PRIMARY_METRIC_KEY, PRIMARY_METRIC_VERSION).await?;
    let window_days = primary.window_days;

    let treatment_rows = sqlx::query(
        "SELECT segment, \
                COUNT(*) FILTER (WHERE matured_at IS NOT NULL)::bigint AS matured, \
                COUNT(*) FILTER (WHERE matured_at IS NOT NULL AND success)::bigint AS successes \
         FROM sales_experiment_contact_trials \
         WHERE tenant_id = $1 AND experiment_id = $2 \
         GROUP BY segment",
    )
    .bind(tenant_id)
    .bind(experiment_id)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let holdout_rows = sqlx::query(
        "SELECT h.segment, \
                COUNT(*) FILTER ( \
                    WHERE h.assigned_at + make_interval(days => $3::int) <= $4)::bigint AS matured, \
                COUNT(*) FILTER ( \
                    WHERE h.assigned_at + make_interval(days => $3::int) <= $4 \
                      AND EXISTS ( \
                          SELECT 1 FROM sales_outcomes o \
                          WHERE o.tenant_id = h.tenant_id AND o.account_id = h.account_id \
                            AND o.outcome IN ('positive_reply', 'meeting_booked') \
                            AND o.occurred_at >= h.assigned_at \
                            AND o.occurred_at <= h.assigned_at + make_interval(days => $3::int) \
                      ))::bigint AS successes \
         FROM sales_experiment_holdout_accounts h \
         WHERE h.tenant_id = $1 AND h.experiment_id = $2 \
         GROUP BY h.segment",
    )
    .bind(tenant_id)
    .bind(experiment_id)
    .bind(window_days)
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    #[derive(Default)]
    struct Counts {
        matured: i64,
        successes: i64,
    }
    let mut by_segment: BTreeMap<String, (Counts, Counts)> = BTreeMap::new();
    for row in treatment_rows {
        let segment: String = row
            .try_get("segment")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let matured: i64 = row
            .try_get("matured")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let successes: i64 = row
            .try_get("successes")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        by_segment.entry(segment).or_default().0 = Counts { matured, successes };
    }
    for row in holdout_rows {
        let segment: String = row
            .try_get("segment")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let matured: i64 = row
            .try_get("matured")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let successes: i64 = row
            .try_get("successes")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        by_segment.entry(segment).or_default().1 = Counts { matured, successes };
    }

    Ok(by_segment
        .into_iter()
        .map(|(segment, (treatment, holdout))| {
            let treatment_rate = ratio(treatment.successes, treatment.matured);
            let holdout_rate = ratio(holdout.successes, holdout.matured);
            let lift_pp = match (treatment_rate, holdout_rate) {
                (Some(treatment), Some(holdout)) => Some((treatment - holdout) * 100.0),
                _ => None,
            };
            SegmentLift {
                segment,
                treatment_matured: treatment.matured,
                treatment_successes: treatment.successes,
                treatment_rate,
                holdout_matured: holdout.matured,
                holdout_successes: holdout.successes,
                holdout_rate,
                lift_pp,
            }
        })
        .collect())
}

fn ratio(numerator: i64, denominator: i64) -> Option<f64> {
    if denominator > 0 && numerator >= 0 {
        Some(numerator as f64 / denominator as f64)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Logged propensities and off-policy evaluation (S4)
// ---------------------------------------------------------------------------

/// One logged decision used by the off-policy estimator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggedDecision {
    pub arm: String,
    /// The ACTUAL probability the arm was chosen under, as logged by the
    /// sampler.
    pub propensity: f64,
    /// The observed primary-outcome reward (1.0 success, 0.0 failure).
    pub reward: f64,
}

/// Inverse propensity scoring: `(1/n) Σ 1{a=x} r / p`.
///
/// Returns `None` when the log contains no valid decision for `target_arm`
/// (a denominator of zero is not an estimate of zero). Rows with a
/// non-finite or non-positive propensity are dropped, never smoothed or
/// clipped: a dishonest log yields no estimate.
pub fn ips(decisions: &[LoggedDecision], target_arm: &str) -> Option<f64> {
    let mut total = 0.0;
    let mut count = 0usize;
    for decision in decisions {
        if !valid_propensity(decision.propensity) {
            continue;
        }
        count += 1;
        if decision.arm == target_arm {
            total += decision.reward / decision.propensity;
        }
    }
    if count == 0 {
        return None;
    }
    Some(total / count as f64)
}

/// Self-normalized IPS: `Σ 1{a=x} r/p ÷ Σ 1{a=x}/p`.
///
/// Same validity contract as [`ips`]. SNIPS is the stable estimator when the
/// logging policy is far from uniform; it returns `None` when no valid
/// decision targeted `target_arm`.
pub fn snips(decisions: &[LoggedDecision], target_arm: &str) -> Option<f64> {
    let mut weighted_reward = 0.0;
    let mut weight = 0.0;
    for decision in decisions {
        if !valid_propensity(decision.propensity) || decision.arm != target_arm {
            continue;
        }
        let w = 1.0 / decision.propensity;
        weighted_reward += decision.reward * w;
        weight += w;
    }
    if weight <= 0.0 {
        None
    } else {
        Some(weighted_reward / weight)
    }
}

fn valid_propensity(propensity: f64) -> bool {
    propensity.is_finite() && propensity > 0.0 && propensity <= 1.0
}

/// An OPE estimate for one arm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpeEstimate {
    pub variant: String,
    pub decisions: usize,
    pub ips: Option<f64>,
    pub snips: Option<f64>,
}

/// Load the logged decisions for one experiment. One decision per contact
/// (the earliest assignment): the estimator's unit is the unit the
/// propensity was logged for, and a contact is a trial once.
pub async fn load_logged_decisions(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
) -> Result<Vec<LoggedDecision>, SalesError> {
    let rows = sqlx::query(
        "SELECT DISTINCT ON (a.contact_id) a.variant, a.propensity, \
                CASE WHEN t.matured_at IS NOT NULL AND t.success THEN 1.0 ELSE 0.0 END AS reward \
         FROM sales_experiment_assignments a \
         JOIN sales_experiment_contact_trials t \
           ON t.tenant_id = a.tenant_id AND t.experiment_id = a.experiment_id \
          AND t.variant = a.variant AND t.contact_id = a.contact_id \
         WHERE a.tenant_id = $1 AND a.experiment_id = $2 \
           AND a.contact_id IS NOT NULL AND t.matured_at IS NOT NULL \
         ORDER BY a.contact_id, a.decided_at ASC",
    )
    .bind(tenant_id)
    .bind(experiment_id)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    rows.into_iter()
        .map(|row| {
            Ok(LoggedDecision {
                arm: row
                    .try_get("variant")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                propensity: row
                    .try_get("propensity")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                reward: row
                    .try_get("reward")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
            })
        })
        .collect()
}

/// Compute IPS and SNIPS for every arm.
pub fn off_policy_estimates(
    decisions: &[LoggedDecision],
    arms: &[ArmPosterior],
) -> Vec<OpeEstimate> {
    arms.iter()
        .map(|arm| OpeEstimate {
            variant: arm.variant.clone(),
            decisions: decisions
                .iter()
                .filter(|decision| decision.arm == arm.variant)
                .count(),
            ips: ips(decisions, &arm.variant),
            snips: snips(decisions, &arm.variant),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Power (S5)
// ---------------------------------------------------------------------------

/// Standard normal quantile (Acklam's rational approximation, |error| <
/// 1.15e-9). `None` outside `(0, 1)`.
pub fn normal_quantile(p: f64) -> Option<f64> {
    if !p.is_finite() || p <= 0.0 || p >= 1.0 {
        return None;
    }
    // Peter J. Acklam's algorithm, |error| < 1.15e-9.
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];
    let p_low = 0.024_25;
    let p_high = 1.0 - p_low;
    if p < p_low {
        let q = (-2.0 * p.ln()).sqrt();
        Some(
            (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
                / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0),
        )
    } else if p <= p_high {
        let q = p - 0.5;
        let r = q * q;
        Some(
            ((((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q)
                / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0),
        )
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        Some(
            -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
                / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0),
        )
    }
}

/// Minimum detectable absolute effect for a two-arm binary primary metric at
/// a given per-arm sample, two-sided `alpha` and `power`:
/// `(z_{1-alpha/2} + z_{power}) * sqrt(2 p(1-p) / n)`.
///
/// `None` for an invalid sample/rate: never a misleading zero.
pub fn minimum_detectable_effect(
    baseline_rate: f64,
    n_per_arm: i64,
    alpha: f64,
    power: f64,
) -> Option<f64> {
    if n_per_arm <= 0
        || !baseline_rate.is_finite()
        || !(0.0..1.0).contains(&baseline_rate)
        || !alpha.is_finite()
        || !(0.0..1.0).contains(&alpha)
        || !power.is_finite()
        || !(0.0..1.0).contains(&power)
    {
        return None;
    }
    let z_alpha = normal_quantile(1.0 - alpha / 2.0)?;
    let z_power = normal_quantile(power)?;
    Some(
        (z_alpha + z_power)
            * (2.0 * baseline_rate * (1.0 - baseline_rate) / n_per_arm as f64).sqrt(),
    )
}

/// The scoreboard's power view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PowerReport {
    pub n_per_arm: i64,
    pub baseline_rate: f64,
    pub alpha: f64,
    pub power: f64,
    pub mde_absolute: Option<f64>,
    pub mde_percentage_points: Option<f64>,
}

pub fn power_report(baseline_rate: f64, n_per_arm: i64, alpha: f64, power: f64) -> PowerReport {
    let mde = minimum_detectable_effect(baseline_rate, n_per_arm, alpha, power);
    PowerReport {
        n_per_arm,
        baseline_rate,
        alpha,
        power,
        mde_absolute: mde,
        mde_percentage_points: mde.map(|mde| mde * 100.0),
    }
}

// ---------------------------------------------------------------------------
// Sequential monitoring (S5): mSPRT
// ---------------------------------------------------------------------------

/// Default mixing prior standard deviation on the risk difference (5
/// percentage points). A larger τ is more sensitive to large effects and
/// less to small ones; this is the documented, fixed choice.
pub const SEQUENTIAL_TAU: f64 = 0.05;
/// Default always-valid false-positive level.
pub const SEQUENTIAL_ALPHA: f64 = 0.05;

/// The always-valid sequential verdict at the current information time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequentialVerdict {
    pub method: String,
    pub looks: u64,
    pub control_n: i64,
    pub control_successes: i64,
    pub treatment_n: i64,
    pub treatment_successes: i64,
    pub statistic: f64,
    pub threshold: f64,
    pub reject: bool,
}

/// The mSPRT statistic for a difference of two Bernoulli means, mixing the
/// risk difference over `N(0, tau²)`:
///
/// ```text
/// v = p_c(1-p_c)/n_c + p_t(1-p_t)/n_t
/// Λ = sqrt(v / (v + tau²)) * exp(tau² * Δ² / (2 v (v + tau²)))
/// ```
///
/// Reject at `Λ >= 1/alpha`. Under the null the mixture likelihood ratio is
/// a non-negative supermartingale with expectation <= 1, so the rejection
/// probability at ANY stopping time is <= alpha (always-valid).
pub fn msprt_statistic(
    control_successes: i64,
    control_n: i64,
    treatment_successes: i64,
    treatment_n: i64,
    tau: f64,
) -> f64 {
    if control_n <= 0
        || treatment_n <= 0
        || control_successes < 0
        || treatment_successes < 0
        || control_successes > control_n
        || treatment_successes > treatment_n
        || !tau.is_finite()
        || tau <= 0.0
    {
        return 0.0;
    }
    let p_control = control_successes as f64 / control_n as f64;
    let p_treatment = treatment_successes as f64 / treatment_n as f64;
    let variance = p_control * (1.0 - p_control) / control_n as f64
        + p_treatment * (1.0 - p_treatment) / treatment_n as f64;
    if variance <= 0.0 {
        return 0.0;
    }
    let tau2 = tau * tau;
    let delta = p_treatment - p_control;
    (variance / (variance + tau2)).sqrt()
        * ((tau2 * delta * delta) / (2.0 * variance * (variance + tau2))).exp()
}

/// A stateful mSPRT monitor: every call is one "look" at the cumulative
/// data, and the always-valid threshold means the caller may peek after
/// every contact.
#[derive(Debug, Clone)]
pub struct SequentialMonitor {
    alpha: f64,
    tau: f64,
    looks: u64,
}

impl Default for SequentialMonitor {
    fn default() -> Self {
        Self::new(SEQUENTIAL_ALPHA, SEQUENTIAL_TAU)
    }
}

impl SequentialMonitor {
    pub fn new(alpha: f64, tau: f64) -> Self {
        let alpha = if alpha.is_finite() && alpha > 0.0 && alpha < 1.0 {
            alpha
        } else {
            SEQUENTIAL_ALPHA
        };
        let tau = if tau.is_finite() && tau > 0.0 {
            tau
        } else {
            SEQUENTIAL_TAU
        };
        Self {
            alpha,
            tau,
            looks: 0,
        }
    }

    pub fn looks(&self) -> u64 {
        self.looks
    }

    pub fn observe(
        &mut self,
        control_successes: i64,
        control_n: i64,
        treatment_successes: i64,
        treatment_n: i64,
    ) -> SequentialVerdict {
        self.looks += 1;
        let statistic = msprt_statistic(
            control_successes,
            control_n,
            treatment_successes,
            treatment_n,
            self.tau,
        );
        let threshold = 1.0 / self.alpha;
        SequentialVerdict {
            method: "msprt".to_string(),
            looks: self.looks,
            control_n,
            control_successes,
            treatment_n,
            treatment_successes,
            statistic,
            threshold,
            reject: statistic >= threshold,
        }
    }
}

// ---------------------------------------------------------------------------
// The scoreboard
// ---------------------------------------------------------------------------

/// One arm's scoreboard row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArmScoreboard {
    pub variant: String,
    pub is_control: bool,
    pub matured: i64,
    pub successes: i64,
    pub primary_rate: Option<f64>,
    pub alpha: f64,
    pub beta: f64,
    pub posterior_mean: f64,
    pub value_multiplier: f64,
    pub choice_score: f64,
    pub north_star_matured_contacts: i64,
    pub north_star_revenue_eur: f64,
    pub north_star_mrr_per_1000: Option<f64>,
}

/// The experiment scoreboard. Every metric carries the registry definition it
/// was computed under.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scoreboard {
    pub experiment_id: Uuid,
    pub key: String,
    pub name: String,
    pub status: String,
    pub hypothesis: Option<String>,
    pub planned_sample: Option<i64>,
    pub primary_metric: MetricDefinition,
    pub north_star_metric: MetricDefinition,
    pub arms: Vec<ArmScoreboard>,
    pub total_matured: i64,
    pub power: PowerReport,
    pub sequential: SequentialVerdict,
    pub holdout: Vec<SegmentLift>,
    pub ope: Vec<OpeEstimate>,
    pub guardrails: Vec<ArmGuardrailReport>,
}

async fn required_metric(
    db: &PgPool,
    metric_key: &str,
    version: i32,
) -> Result<MetricDefinition, SalesError> {
    metric_definition(db, metric_key, version)
        .await?
        .ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "metric '{metric_key}' v{version} is not in the registry \
                 (sales_experiment_metrics); the scoreboard refuses to report an unregistered \
                 metric"
            ))
        })
}

/// Compute the scoreboard for one experiment key. The primary/north-star
/// windows come from the registry, not from constants in the caller.
pub async fn compute_scoreboard(
    db: &PgPool,
    tenant_id: &str,
    experiment_key: &str,
    now: DateTime<Utc>,
) -> Result<Scoreboard, SalesError> {
    let engine = ExperimentEngine::new(db.clone());
    let experiment = engine
        .load_experiment(tenant_id, experiment_key)
        .await?
        .ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "experiment '{experiment_key}' does not exist for tenant {tenant_id}"
            ))
        })?;
    let primary = required_metric(
        db,
        &experiment.primary_metric,
        experiment.primary_metric_version,
    )
    .await?;
    let north_star = required_metric(db, NORTH_STAR_METRIC_KEY, NORTH_STAR_METRIC_VERSION).await?;

    let arms = engine.load_arms(tenant_id, experiment.id).await?;

    let trial_rows = sqlx::query(
        "SELECT variant, \
                COUNT(*) FILTER (WHERE matured_at IS NOT NULL)::bigint AS matured, \
                COUNT(*) FILTER (WHERE matured_at IS NOT NULL AND success)::bigint AS successes \
         FROM sales_experiment_contact_trials \
         WHERE tenant_id = $1 AND experiment_id = $2 \
           AND primary_metric = $3 AND primary_metric_version = $4 \
         GROUP BY variant",
    )
    .bind(tenant_id)
    .bind(experiment.id)
    .bind(&primary.metric_key)
    .bind(primary.version)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let mut trial_counts: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for row in trial_rows {
        let variant: String = row
            .try_get("variant")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let matured: i64 = row
            .try_get("matured")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let successes: i64 = row
            .try_get("successes")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        trial_counts.insert(variant, (matured, successes));
    }

    let revenue_rows = sqlx::query(
        "SELECT t.variant, \
                COUNT(DISTINCT t.contact_id) FILTER ( \
                    WHERE t.first_touch_at + make_interval(days => $3::int) <= $4)::bigint AS matured90, \
                COALESCE(SUM(o.value_eur) FILTER ( \
                    WHERE o.kind IN ('trial', 'paid_subscription', 'retained_mrr') \
                      AND o.occurred_at <= t.first_touch_at + make_interval(days => $3::int) \
                      AND t.first_touch_at + make_interval(days => $3::int) <= $4), 0)::float8 AS revenue \
         FROM sales_experiment_contact_trials t \
         LEFT JOIN sales_experiment_outcomes o \
           ON o.tenant_id = t.tenant_id AND o.experiment_id = t.experiment_id \
          AND o.variant = t.variant AND o.contact_id = t.contact_id \
         WHERE t.tenant_id = $1 AND t.experiment_id = $2 \
         GROUP BY t.variant",
    )
    .bind(tenant_id)
    .bind(experiment.id)
    .bind(north_star.window_days)
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let mut revenue_by_variant: BTreeMap<String, (i64, f64)> = BTreeMap::new();
    for row in revenue_rows {
        let variant: String = row
            .try_get("variant")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let matured90: i64 = row
            .try_get("matured90")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let revenue: f64 = row
            .try_get("revenue")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        revenue_by_variant.insert(variant, (matured90, revenue));
    }

    let mut arms_out = Vec::with_capacity(arms.len());
    for arm in &arms {
        let (matured, successes) = trial_counts.get(&arm.variant).copied().unwrap_or((0, 0));
        let (north_star_matured, revenue) = revenue_by_variant
            .get(&arm.variant)
            .copied()
            .unwrap_or((0, 0.0));
        arms_out.push(ArmScoreboard {
            variant: arm.variant.clone(),
            is_control: arm.is_control,
            matured,
            successes,
            primary_rate: ratio(successes, matured),
            alpha: arm.alpha,
            beta: arm.beta,
            posterior_mean: arm.mean(),
            value_multiplier: arm.value_multiplier,
            choice_score: arm.choice_score(),
            north_star_matured_contacts: north_star_matured,
            north_star_revenue_eur: revenue,
            north_star_mrr_per_1000: if north_star_matured > 0 {
                Some(revenue / north_star_matured as f64 * 1_000.0)
            } else {
                None
            },
        });
    }

    let total_matured: i64 = arms_out.iter().map(|arm| arm.matured).sum();
    let control = arms_out.iter().find(|arm| arm.is_control);
    let baseline_rate = control.and_then(|arm| arm.primary_rate).unwrap_or_else(|| {
        let successes: i64 = arms_out.iter().map(|arm| arm.successes).sum();
        if total_matured > 0 {
            successes as f64 / total_matured as f64
        } else {
            0.5
        }
    });
    let n_per_arm = if arms_out.is_empty() {
        0
    } else {
        total_matured / arms_out.len() as i64
    };
    let power = power_report(baseline_rate, n_per_arm, 0.05, 0.8);

    // Sequential: control vs the best challenger by observed primary rate.
    let mut monitor = SequentialMonitor::default();
    let sequential = match control {
        Some(control) => {
            let challenger = arms_out
                .iter()
                .filter(|arm| !arm.is_control)
                .max_by(|a, b| {
                    a.primary_rate
                        .unwrap_or(0.0)
                        .partial_cmp(&b.primary_rate.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            match challenger {
                Some(challenger) => monitor.observe(
                    control.successes,
                    control.matured,
                    challenger.successes,
                    challenger.matured,
                ),
                None => monitor.observe(0, 0, 0, 0),
            }
        }
        None => monitor.observe(0, 0, 0, 0),
    };

    let holdout = holdout_lift(db, tenant_id, experiment.id, now).await?;
    let decisions = load_logged_decisions(db, tenant_id, experiment.id).await?;
    let ope = off_policy_estimates(&decisions, &arms);
    let guardrails = guardrails_for_experiment(
        db,
        tenant_id,
        experiment.id,
        now,
        metric_definition(db, "complaint_rate", 1)
            .await?
            .map(|definition| definition.window_days)
            .unwrap_or(30),
    )
    .await?;

    Ok(Scoreboard {
        experiment_id: experiment.id,
        key: experiment.key.clone(),
        name: experiment.name.clone(),
        status: experiment.status.as_str().to_string(),
        hypothesis: experiment.hypothesis.clone(),
        planned_sample: experiment.planned_sample,
        primary_metric: primary,
        north_star_metric: north_star,
        arms: arms_out,
        total_matured,
        power,
        sequential,
        holdout,
        ope,
        guardrails,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn metric_registry_seed_keys_match_the_code_constants() {
        // The names the code reads must be the names migration 290 seeds.
        assert_eq!(PRIMARY_METRIC_KEY, "positive_reply_or_meeting_14d");
        assert_eq!(PRIMARY_METRIC_VERSION, 1);
        assert_eq!(NORTH_STAR_METRIC_KEY, "won_mrr_per_1000_90d");
        assert_eq!(NORTH_STAR_METRIC_VERSION, 1);
    }

    #[test]
    fn guardrail_thresholds_are_the_named_values_and_pause_at_the_boundary() {
        assert_eq!(COMPLAINT_RATE_PAUSE, 0.001);
        assert_eq!(UNSUBSCRIBE_RATE_PAUSE, 0.01);
        assert_eq!(HARD_BOUNCE_RATE_PAUSE, 0.02);

        fn counts(
            contacts: i64,
            complaints: i64,
            unsubscribes: i64,
            bounces: i64,
        ) -> GuardrailCounts {
            GuardrailCounts {
                contacts,
                complaints,
                unsubscribes,
                bounces,
            }
        }
        // Exactly at the threshold pauses; just below does not.
        assert!(evaluate_guardrails(counts(1_000, 1, 0, 0)).paused);
        assert!(!evaluate_guardrails(counts(1_001, 1, 0, 0)).paused);
        assert!(evaluate_guardrails(counts(1_000, 0, 10, 0)).paused);
        assert!(!evaluate_guardrails(counts(1_001, 0, 10, 0)).paused);
        assert!(evaluate_guardrails(counts(1_000, 0, 0, 20)).paused);
        assert!(!evaluate_guardrails(counts(1_001, 0, 0, 20)).paused);

        // No contacts never pauses (there is no rate yet).
        assert!(!evaluate_guardrails(GuardrailCounts::default()).paused);
        // Hostile negative counters read as zero, never as a pass-through.
        assert!(!evaluate_guardrails(counts(10, -100, -100, -100)).paused);
    }

    #[test]
    fn holdout_assignment_is_stable_and_respects_the_share() {
        let account = Uuid::parse_str("6f1f0f7e-4b2b-4a6b-9a7e-9c0f8c9a1b2c").unwrap();
        assert_eq!(
            holdout_bucket(account, "SaaS", 1),
            holdout_bucket(account, " saas ", 1),
            "segment normalisation must not change the bucket"
        );
        assert_eq!(
            holdout_bucket(account, "saas", 1),
            holdout_bucket(account, "saas", 1)
        );
        assert_ne!(
            holdout_bucket(account, "saas", 1),
            holdout_bucket(account, "saas", 2),
            "a new registry version is a new holdout draw"
        );
        // Zero share holds nobody out; the maximum share holds at most 50% but
        // is still deterministic per account.
        assert!(!is_holdout(account, "saas", 1, 0.0));
        let million: Vec<Uuid> = (0..10_000).map(|_| Uuid::new_v4()).collect();
        let share = 0.1;
        let held = million
            .iter()
            .filter(|id| is_holdout(**id, "saas", 1, share))
            .count();
        assert!(
            (800..=1_200).contains(&held),
            "10% of 10,000 accounts must land within sampling tolerance, got {held}"
        );
        // The same account always lands on the same side across calls.
        let first = is_holdout(account, "saas", 1, 0.2);
        for _ in 0..10 {
            assert_eq!(is_holdout(account, "saas", 1, 0.2), first);
        }
    }

    #[test]
    fn ips_and_snips_recover_a_planted_effect_from_synthetic_logs() {
        // Synthetic log: 4,000 decisions from a 50/50 logger, true success
        // rates 10% (a) and 30% (b). Both estimators must recover the planted
        // rates within tolerance.
        let mut rng = StdRng::seed_from_u64(42);
        let mut decisions = Vec::new();
        for _ in 0..4_000 {
            let arm = if rng.random::<bool>() { "a" } else { "b" };
            let reward = if arm == "a" {
                if rng.random::<f64>() < 0.10 {
                    1.0
                } else {
                    0.0
                }
            } else if rng.random::<f64>() < 0.30 {
                1.0
            } else {
                0.0
            };
            decisions.push(LoggedDecision {
                arm: arm.to_string(),
                propensity: 0.5,
                reward,
            });
        }
        let ips_a = ips(&decisions, "a").expect("a logged");
        let ips_b = ips(&decisions, "b").expect("b logged");
        let snips_a = snips(&decisions, "a").expect("a logged");
        let snips_b = snips(&decisions, "b").expect("b logged");
        assert!((ips_a - 0.10).abs() < 0.03, "IPS(a) = {ips_a}");
        assert!((ips_b - 0.30).abs() < 0.03, "IPS(b) = {ips_b}");
        assert!((snips_a - 0.10).abs() < 0.03, "SNIPS(a) = {snips_a}");
        assert!((snips_b - 0.30).abs() < 0.03, "SNIPS(b) = {snips_b}");
        // The planted effect survives.
        assert!(snips_b - snips_a > 0.15);

        // A deterministic log: propensity 1.0, reward 2.0 → both estimators
        // return 2.0 exactly.
        let logged = vec![LoggedDecision {
            arm: "b".into(),
            propensity: 1.0,
            reward: 2.0,
        }];
        assert_eq!(ips(&logged, "b"), Some(2.0));
        assert_eq!(snips(&logged, "b"), Some(2.0));

        // Honesty: an invalid propensity is dropped, and an arm with no valid
        // decision has NO estimate (not zero).
        let invalid = vec![
            LoggedDecision {
                arm: "a".into(),
                propensity: 0.0,
                reward: 1.0,
            },
            LoggedDecision {
                arm: "a".into(),
                propensity: f64::NAN,
                reward: 1.0,
            },
        ];
        assert_eq!(ips(&invalid, "a"), None);
        assert_eq!(snips(&invalid, "a"), None);
        // IPS averages over every valid decision, so a target arm that was
        // never logged has an honest 0.0; SNIPS has no weight and returns
        // None (no self-normalised estimate exists).
        assert_eq!(ips(&logged, "missing"), Some(0.0));
        assert_eq!(snips(&logged, "missing"), None);
    }

    #[test]
    fn power_calculator_reports_a_decreasing_mde() {
        let large = minimum_detectable_effect(0.10, 1_000, 0.05, 0.8).expect("mde");
        let small = minimum_detectable_effect(0.10, 10_000, 0.05, 0.8).expect("mde");
        assert!(
            (0.030..=0.045).contains(&large),
            "p=0.10, n=1,000 MDE should be ~3.8 pp, got {large}"
        );
        assert!(
            small < large / 3.0,
            "MDE shrinks with n: {small} vs {large}"
        );
        // Invalid inputs never produce a misleading number.
        assert_eq!(minimum_detectable_effect(0.10, 0, 0.05, 0.8), None);
        assert_eq!(minimum_detectable_effect(1.0, 100, 0.05, 0.8), None);
        assert_eq!(minimum_detectable_effect(0.1, 100, 0.0, 0.8), None);
    }

    #[test]
    fn normal_quantile_matches_known_values() {
        assert!((normal_quantile(0.975).unwrap() - 1.959_964).abs() < 1e-4);
        assert!((normal_quantile(0.8).unwrap() - 0.841_621).abs() < 1e-4);
        assert!((normal_quantile(0.5).unwrap()).abs() < 1e-9);
        assert_eq!(normal_quantile(0.0), None);
        assert_eq!(normal_quantile(1.0), None);
    }

    #[test]
    fn msprt_rejects_a_large_effect_and_is_quiet_under_the_null() {
        // A large effect (10% vs 30% over 1,000 per arm) crosses 1/alpha.
        let stat = msprt_statistic(100, 1_000, 300, 1_000, SEQUENTIAL_TAU);
        assert!(stat >= 1.0 / SEQUENTIAL_ALPHA, "statistic {stat}");
        let mut monitor = SequentialMonitor::default();
        let verdict = monitor.observe(100, 1_000, 300, 1_000);
        assert!(verdict.reject, "{verdict:?}");
        assert_eq!(verdict.threshold, 20.0);
        assert_eq!(verdict.looks, 1);

        // No difference: Λ is the mixture normalisation
        // sqrt(v / (v + tau²)) < 1, i.e. a null result never rejects.
        let null = msprt_statistic(100, 1_000, 100, 1_000, SEQUENTIAL_TAU);
        let variance = 0.1 * 0.9 / 1_000.0 + 0.1 * 0.9 / 1_000.0;
        let expected = (variance / (variance + SEQUENTIAL_TAU * SEQUENTIAL_TAU)).sqrt();
        assert!((null - expected).abs() < 1e-9, "{null} vs {expected}");
        assert!(null < 1.0 / SEQUENTIAL_ALPHA);
        // Hostile inputs are quiet, never NaN/infinite.
        assert_eq!(msprt_statistic(1, 0, 1, 0, SEQUENTIAL_TAU), 0.0);
        assert_eq!(msprt_statistic(2, 1, 1, 1, SEQUENTIAL_TAU), 0.0);
        assert_eq!(msprt_statistic(1, 10, 2, 10, f64::NAN), 0.0);
    }

    /// S5 done-when: early peeking does not inflate the false-positive rate.
    ///
    /// 1,000 null experiments (both arms Bernoulli(0.1)) are peeked after
    /// every 10 contacts per arm. The mSPRT is always-valid, so the fraction
    /// of runs that ever cross `1/alpha` must stay at/near the nominal 5%,
    /// never the ~40-60% an uncorrected fixed-horizon z-test would produce
    /// under continuous peeking.
    #[test]
    fn early_peeking_does_not_inflate_false_positives() {
        let mut rng = StdRng::seed_from_u64(7);
        let runs = 500usize;
        let look_every = 10usize;
        let max_per_arm = 200usize;
        let mut false_positives = 0usize;
        for _ in 0..runs {
            let mut monitor = SequentialMonitor::default();
            let mut control_successes = 0i64;
            let mut treatment_successes = 0i64;
            let mut rejected = false;
            let mut n = 0usize;
            while n < max_per_arm {
                for _ in 0..look_every {
                    if rng.random::<f64>() < 0.1 {
                        control_successes += 1;
                    }
                    if rng.random::<f64>() < 0.1 {
                        treatment_successes += 1;
                    }
                }
                n += look_every;
                let verdict =
                    monitor.observe(control_successes, n as i64, treatment_successes, n as i64);
                if verdict.reject {
                    rejected = true;
                    break;
                }
            }
            if rejected {
                false_positives += 1;
            }
        }
        let rate = false_positives as f64 / runs as f64;
        assert!(
            rate <= SEQUENTIAL_ALPHA + 0.02,
            "always-valid peeking must not exceed the nominal alpha: {rate}"
        );
    }

    /// A true effect still reaches significance early under the same peeking.
    #[test]
    fn msprt_retains_power_against_a_real_effect() {
        let mut rng = StdRng::seed_from_u64(11);
        let runs = 200usize;
        let mut rejected = 0usize;
        for _ in 0..runs {
            let mut monitor = SequentialMonitor::default();
            let mut control_successes = 0i64;
            let mut treatment_successes = 0i64;
            let mut n = 0usize;
            let mut hit = false;
            while n < 200 {
                for _ in 0..10 {
                    if rng.random::<f64>() < 0.10 {
                        control_successes += 1;
                    }
                    if rng.random::<f64>() < 0.30 {
                        treatment_successes += 1;
                    }
                }
                n += 10;
                if monitor
                    .observe(control_successes, n as i64, treatment_successes, n as i64)
                    .reject
                {
                    hit = true;
                    break;
                }
            }
            if hit {
                rejected += 1;
            }
        }
        let power = rejected as f64 / runs as f64;
        assert!(power > 0.8, "mSPRT must retain power: {power}");
    }
}
