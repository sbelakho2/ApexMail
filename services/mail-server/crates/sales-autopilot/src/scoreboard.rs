//! §S2–S5, experiment science: the ONE metric registry, frozen windows,
//! guardrail pauses, the randomized holdout, logged propensities with
//! off-policy evaluation, the experiment registry, power and an APPROXIMATE
//! sequential diagnostic.
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
//! The stable SHA-256 hash of `account id | segment | registry version`
//! ([`holdout_bucket`]) decides the **initial** randomized membership only.
//! [`crate::experiments::ExperimentEngine::select_variant`] first reads the
//! persisted membership row for `(experiment_id, account_id)`; when one
//! exists it is authoritative forever, so a later enrichment that changes
//! the segment (or the registry version) cannot flip treatment into holdout
//! or the reverse. The segment stays an analysis stratum, never a
//! re-randomization. The holdout branch receives no sending;
//! [`holdout_lift`] reports treatment-vs-holdout lift per segment using
//! matured windows only and counts only persisted `assignment = 'holdout'`
//! members.
//!
//! # Cohort provenance (item 29)
//!
//! `sales_experiment_contact_trials.cohort_source` separates trials whose
//! first touch was OBSERVED by the live send path (`native`) from trials
//! migration 290 rebuilt out of historical outcomes
//! (`reconstructed_legacy`, where `first_touch_at` is the earliest
//! recoverable outcome time and is therefore INFERRED). [`cohort_provenance`]
//! summarizes the split and [`Scoreboard::cohort`] ships it to every API
//! consumer; a mixed experiment is labeled as such rather than passing a
//! reconstructed cohort off as a native one.
//!
//! # Propensities and off-policy evaluation (S4)
//!
//! Every selection records the actual Thompson win probability of each arm
//! (`sales_experiment_assignments.propensities`, plus the chosen arm's
//! `propensity` on the step execution and enrollment). The estimate is a
//! finite Monte-Carlo mean over 2,000 draws: a rare arm can win 0 draws, so
//! the RAW estimate would be an exact zero even though the true selection
//! probability is positive. The engine therefore logs the win count, draw
//! count, Monte-Carlo standard error `sqrt(p(1-p)/n)` and an under-sampled
//! flag, and bounds the logged propensity below by
//! `PROPENSITY_FLOOR_EPSILON`. [`ips`] and [`snips`] are then computed over
//! those bounded logs:
//!
//! ```text
//! IPS  = (1/n) Σ 1{a_i = x} r_i / p_i
//! SNIPS = Σ 1{a_i = x} r_i / p_i  /  Σ 1{a_i = x} / p_i
//! ```
//!
//! A logged propensity must be strictly positive (the deterministic exploit
//! path logs 1.0), and an invalid row is dropped rather than silently
//! reweighted. [`OpeDiagnostics`] accompanies every estimate with the
//! maximum inverse weight, the weight p95, the effective sample size
//! `(Σw)² / Σw²`, and IPS at two clipping levels (`IPS_CLIP_WEIGHT` and half
//! of it) so a conclusion that only survives one clipping is visibly
//! fragile.
//!
//! # Power and the sequential diagnostic (S5)
//!
//! [`minimum_detectable_effect`] reports the absolute MDE for the primary
//! metric at the current per-arm sample. [`SequentialDiagnosticMonitor`] is
//! an **APPROXIMATE normal-approximation sequential diagnostic** with
//! plug-in variance, mixing the risk difference over `δ ~ N(0, τ²)`. It is
//! deliberately **not** called an mSPRT: the implementation provides NO
//! anytime-valid false-positive guarantee (the variance is estimated from
//! the same data and the statistic is not a calibrated test supermartingale),
//! and the `1/α` boundary is NOT a promotion warrant. Promotion goes
//! through the registered sample and credible-interval gate in
//! `crate::experiments::may_promote_arm`, never through this diagnostic. The
//! simulation test
//! `approximate_sequential_diagnostic_is_calibrated_on_a_peeking_grid` is a
//! calibration CHECK on one simulated grid; it is not a validity proof.

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
                COUNT(o.outcome_key) FILTER (WHERE o.kind = 'complaint')::bigint AS complaints, \
                COUNT(o.outcome_key) FILTER (WHERE o.kind = 'unsubscribe')::bigint AS unsubscribes, \
                COUNT(o.outcome_key) FILTER (WHERE o.kind = 'bounce')::bigint AS bounces \
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
///
/// This is the INITIAL randomization draw only. Membership is persisted by
/// `ExperimentEngine::select_variant` and never recomputed for an account
/// that already has a row; the bucket must not be used as a live membership
/// test by any other caller.
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

/// Would a NEVER-SEEN account land in the holdout at its first decision?
/// `share` is sanitised to `0.0..=0.5`; a zero share never holds anyone out,
/// and a hostile share cannot exceed half the segment.
///
/// This must only be used for the INITIAL assignment. The selection path
/// checks the persisted `sales_experiment_holdout_accounts` row FIRST and
/// treats an existing row as authoritative, so a segment change cannot flip
/// membership. Calling this as a live predicate would reintroduce the
/// randomization defect it is documented against.
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
///
/// Only persisted `assignment = 'holdout'` members are counted. The ledger
/// also stores `treatment` members (so their membership is immutable too);
/// those are not held out and must not enter this lift.
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
           AND h.assignment = 'holdout' \
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
// Cohort provenance (item 29)
// ---------------------------------------------------------------------------

/// The trial was created by the live send/outcome path, which observed the
/// first touch.
pub const COHORT_SOURCE_NATIVE: &str = "native";
/// Migration 290 rebuilt the trial from historical outcome rows; its
/// `first_touch_at` is the earliest recoverable outcome, not an observed
/// first touch.
pub const COHORT_SOURCE_RECONSTRUCTED_LEGACY: &str = "reconstructed_legacy";

/// How much of an experiment's trial ledger is native versus reconstructed.
/// Shipped on every [`Scoreboard`] so a dashboard or API consumer can label
/// (or filter out) the reconstructed cohort instead of silently comparing it
/// with natively randomized trials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortProvenance {
    /// Trials whose first touch the live path observed.
    pub native_trials: i64,
    /// Trials rebuilt by migration 290 (INFERRED first touch).
    pub reconstructed_legacy_trials: i64,
    /// True when the experiment mixes both sources: rates computed over the
    /// pooled ledger then compare two different kinds of cohort.
    pub mixed: bool,
    /// Dashboard/API label: `none`, `native`, `reconstructed_legacy` or
    /// `mixed`.
    pub label: String,
    /// Human-readable caveat, present whenever reconstructed trials exist.
    pub caveat: Option<String>,
}

/// Count the trial ledger by provenance. Any value other than the literal
/// `native` counts as reconstructed: an unknown provenance must never pass
/// as an observed first touch.
pub async fn cohort_provenance(
    db: &PgPool,
    tenant_id: &str,
    experiment_id: Uuid,
) -> Result<CohortProvenance, SalesError> {
    let row = sqlx::query(
        "SELECT \
             COUNT(*) FILTER (WHERE cohort_source = 'native')::bigint AS native_trials, \
             COUNT(*) FILTER (WHERE cohort_source <> 'native')::bigint AS reconstructed_trials \
         FROM sales_experiment_contact_trials \
         WHERE tenant_id = $1 AND experiment_id = $2",
    )
    .bind(tenant_id)
    .bind(experiment_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let native_trials: i64 = row
        .try_get("native_trials")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let reconstructed_legacy_trials: i64 = row
        .try_get("reconstructed_trials")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let mixed = native_trials > 0 && reconstructed_legacy_trials > 0;
    let label = match (native_trials > 0, reconstructed_legacy_trials > 0) {
        (false, false) => "none",
        (true, false) => COHORT_SOURCE_NATIVE,
        (false, true) => COHORT_SOURCE_RECONSTRUCTED_LEGACY,
        (true, true) => "mixed",
    }
    .to_string();
    let caveat = (reconstructed_legacy_trials > 0).then(|| {
        format!(
            "{reconstructed_legacy_trials} trial(s) were reconstructed by migration 290 from \
             historical outcomes: first_touch_at is the EARLIEST RECOVERABLE outcome, not an \
             observed first touch. Rates that pool reconstructed and native trials are not a \
             clean randomized comparison; report or filter the provenance."
        )
    });
    Ok(CohortProvenance {
        native_trials,
        reconstructed_legacy_trials,
        mixed,
        label,
        caveat,
    })
}

// ---------------------------------------------------------------------------
// Logged propensities and off-policy evaluation (S4)
// ---------------------------------------------------------------------------

/// One logged decision used by the off-policy estimator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggedDecision {
    pub arm: String,
    /// The ACTUAL probability the arm was chosen under, as logged by the
    /// sampler. The selection path bounds it below by
    /// `crate::experiments::PROPENSITY_FLOOR_EPSILON`, so IPS/SNIPS never
    /// divide by a false exact zero.
    pub propensity: f64,
    /// The observed primary-outcome reward (1.0 success, 0.0 failure).
    pub reward: f64,
    /// Monte-Carlo wins behind the logged propensity (the estimate's
    /// effective sample size). `None` for rows written before migration 293.
    #[serde(default)]
    pub propensity_wins: Option<i64>,
    /// Monte-Carlo draws behind the logged propensity.
    #[serde(default)]
    pub propensity_draws: Option<i64>,
    /// TRUE when the Monte-Carlo estimate had 0 wins, i.e. the raw estimate
    /// was a false exact zero and the logged value is the epsilon floor.
    #[serde(default)]
    pub propensity_undersampled: bool,
}

/// Default inverse-weight clip used for the clipped-IPS sensitivity check.
pub const IPS_CLIP_WEIGHT: f64 = 10.0;
/// Relative change between the two clipping levels above which a conclusion
/// is reported as clipping-sensitive.
pub const IPS_CLIP_SENSITIVITY_TOLERANCE: f64 = 0.10;

/// Uncertainty diagnostics for one arm's IPS/SNIPS estimate.
///
/// The weights are `w_i = 1{a_i = x} / p_i` over the valid logged decisions.
/// `effective_sample_size = (Σw)² / Σw²` is the usual importance-weight ESS:
/// it collapses toward 1 when a few huge weights dominate, which is exactly
/// when IPS is unreliable even though `n` looks large.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpeDiagnostics {
    /// Valid logged decisions (the IPS denominator `n`).
    pub valid_decisions: usize,
    /// Decisions that selected `target_arm`.
    pub arm_decisions: usize,
    /// Largest `1/p` among decisions that selected `target_arm`.
    pub max_inverse_weight: f64,
    /// 95th percentile of the target-arm inverse weights (nearest rank).
    pub p95_inverse_weight: Option<f64>,
    /// `(Σw)² / Σw²` over the target-arm weights.
    pub effective_sample_size: f64,
    /// Weight clip `c` used by [`OpeDiagnostics::ips_clipped`].
    pub clip_weight: f64,
    /// IPS with weights clipped at `clip_weight`.
    pub ips_clipped: Option<f64>,
    /// IPS with weights clipped at half the clip (a second, stricter view).
    pub ips_clipped_half: Option<f64>,
    /// TRUE when the two clipping levels disagree by more than
    /// [`IPS_CLIP_SENSITIVITY_TOLERANCE`] relative (or change sign): the
    /// conclusion does not survive the clipping choice.
    pub clipping_sensitive: bool,
    /// Decisions whose logged propensity came from a 0-win Monte-Carlo
    /// estimate (bounded to the epsilon floor).
    pub undersampled_decisions: usize,
    /// Smallest recorded Monte-Carlo win count, `None` when no row carries one.
    pub min_propensity_wins: Option<i64>,
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

/// Clipped IPS: `(1/n) Σ 1{a=x} r · min(1/p, c)`.
///
/// `c` bounds how much one under-sampled decision can move the estimate.
/// The same denominator contract as [`ips`] applies, so the clipped and
/// unclipped values are directly comparable. A non-finite or non-positive
/// clip yields `None` rather than a silent fallback.
pub fn ips_clipped(decisions: &[LoggedDecision], target_arm: &str, clip: f64) -> Option<f64> {
    if !clip.is_finite() || clip <= 0.0 {
        return None;
    }
    let mut total = 0.0;
    let mut count = 0usize;
    for decision in decisions {
        if !valid_propensity(decision.propensity) {
            continue;
        }
        count += 1;
        if decision.arm == target_arm {
            total += decision.reward * (1.0 / decision.propensity).min(clip);
        }
    }
    if count == 0 {
        return None;
    }
    Some(total / count as f64)
}

/// Weight-distribution and clipping diagnostics for one arm.
///
/// A conclusion that only survives one clipping level is visibly fragile:
/// `clipping_sensitive` compares IPS at [`IPS_CLIP_WEIGHT`] with IPS at half
/// that clip and flags a relative change above
/// [`IPS_CLIP_SENSITIVITY_TOLERANCE`] (or a sign change).
pub fn ope_diagnostics(decisions: &[LoggedDecision], target_arm: &str) -> OpeDiagnostics {
    let mut valid_decisions = 0usize;
    let mut arm_decisions = 0usize;
    let mut weights: Vec<f64> = Vec::new();
    let mut undersampled_decisions = 0usize;
    let mut min_propensity_wins: Option<i64> = None;

    for decision in decisions {
        if !valid_propensity(decision.propensity) {
            continue;
        }
        valid_decisions += 1;
        if decision.propensity_undersampled {
            undersampled_decisions += 1;
        }
        if let Some(wins) = decision.propensity_wins {
            min_propensity_wins =
                Some(min_propensity_wins.map_or(wins, |current| current.min(wins)));
        }
        if decision.arm == target_arm {
            arm_decisions += 1;
            weights.push(1.0 / decision.propensity);
        }
    }

    let sum_weights: f64 = weights.iter().sum();
    let sum_squared_weights: f64 = weights.iter().map(|weight| weight * weight).sum();
    let effective_sample_size = if sum_squared_weights > 0.0
        && sum_weights.is_finite()
        && sum_squared_weights.is_finite()
    {
        sum_weights * sum_weights / sum_squared_weights
    } else {
        0.0
    };
    let max_inverse_weight = weights.iter().copied().fold(0.0_f64, f64::max);
    let p95_inverse_weight = if weights.is_empty() {
        None
    } else {
        let mut sorted = weights.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let rank = ((0.95 * sorted.len() as f64).ceil() as usize)
            .max(1)
            .min(sorted.len());
        Some(sorted[rank - 1])
    };

    let ips_clipped_value = ips_clipped(decisions, target_arm, IPS_CLIP_WEIGHT);
    let ips_clipped_half_value = ips_clipped(decisions, target_arm, IPS_CLIP_WEIGHT / 2.0);
    let clipping_sensitive = match (ips_clipped_value, ips_clipped_half_value) {
        (Some(clipped), Some(half)) => {
            let scale = clipped.abs().max(half.abs()).max(f64::MIN_POSITIVE);
            clipped.signum() != half.signum()
                || (clipped - half).abs() > IPS_CLIP_SENSITIVITY_TOLERANCE * scale
        }
        _ => false,
    };

    OpeDiagnostics {
        valid_decisions,
        arm_decisions,
        max_inverse_weight,
        p95_inverse_weight,
        effective_sample_size,
        clip_weight: IPS_CLIP_WEIGHT,
        ips_clipped: ips_clipped_value,
        ips_clipped_half: ips_clipped_half_value,
        clipping_sensitive,
        undersampled_decisions,
        min_propensity_wins,
    }
}

/// An OPE estimate for one arm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpeEstimate {
    pub variant: String,
    pub decisions: usize,
    pub ips: Option<f64>,
    pub snips: Option<f64>,
    /// Weight distribution, effective sample size, clipping sensitivity and
    /// propensity Monte-Carlo quality for this estimate.
    pub diagnostics: OpeDiagnostics,
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
                a.propensity_wins, a.propensity_draws, a.propensity_undersampled, \
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
                propensity_wins: row
                    .try_get("propensity_wins")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                propensity_draws: row
                    .try_get("propensity_draws")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
                propensity_undersampled: row
                    .try_get("propensity_undersampled")
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
            diagnostics: ope_diagnostics(decisions, &arm.variant),
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
// Sequential diagnostic (S5): an APPROXIMATE normal diagnostic, not a test
// with an anytime-valid guarantee.
// ---------------------------------------------------------------------------

/// Fixed method label stored on `sales_experiments.sequential_method` and
/// carried by every verdict. Deliberately descriptive: it names the
/// approximation instead of borrowing the authority of a sequential test.
pub const SEQUENTIAL_DIAGNOSTIC_METHOD: &str = "approximate_normal_sequential_diagnostic";

/// Doc-comment / API disclaimer that ships with the verdict. It says what
/// the number is and, more importantly, what it is not.
pub const SEQUENTIAL_DIAGNOSTIC_INTERPRETATION: &str =
    "Approximate normal-approximation sequential diagnostic: NOT anytime-valid, NOT an mSPRT \
     and NOT a promotion warrant. Repeated peeking at this statistic does not control the \
     false-positive rate; promotion requires the registered sample and credible-interval gate.";

/// Mixing prior standard deviation on the risk difference (5 percentage
/// points) for the approximation. A larger τ is more sensitive to large
/// effects and less to small ones; this is the documented, fixed choice.
pub const SEQUENTIAL_DIAGNOSTIC_TAU: f64 = 0.05;

/// Nominal false-positive level used to place the diagnostic boundary. It is
/// the nominal level of the approximation, NOT a guaranteed Type-I rate.
pub const SEQUENTIAL_DIAGNOSTIC_ALPHA: f64 = 0.05;

/// The boundary `1 / alpha` on the diagnostic statistic. Crossing it is a
/// signal to look more closely, never a decision to promote or stop.
pub const SEQUENTIAL_DIAGNOSTIC_BOUNDARY: f64 = 20.0;

/// The approximate sequential diagnostic at the current information time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequentialDiagnosticVerdict {
    /// Always [`SEQUENTIAL_DIAGNOSTIC_METHOD`]; never a test name.
    pub method: String,
    pub looks: u64,
    pub control_n: i64,
    pub control_successes: i64,
    pub treatment_n: i64,
    pub treatment_successes: i64,
    pub statistic: f64,
    /// The boundary `1 / alpha`; a descriptive threshold, not a critical
    /// value with a Type-I guarantee.
    pub diagnostic_boundary: f64,
    /// `statistic >= diagnostic_boundary`. DELIBERATELY not called
    /// "reject": crossing the line does not reject a null hypothesis with a
    /// controlled error rate.
    pub crosses_boundary: bool,
    /// [`SEQUENTIAL_DIAGNOSTIC_INTERPRETATION`], shipped with the JSON.
    pub interpretation: String,
}

/// The APPROXIMATE normal sequential diagnostic for a difference of two
/// Bernoulli means, mixing the risk difference over `N(0, τ²)`:
///
/// ```text
/// v = p_c(1-p_c)/n_c + p_t(1-p_t)/n_t      (plug-in variance)
/// Λ = sqrt(v / (v + τ²)) * exp(τ² Δ² / (2 v (v + τ²)))
/// ```
///
/// `Λ >= 1/α` is reported by [`SequentialDiagnosticMonitor`] as
/// `crosses_boundary`.
///
/// # What this is NOT
///
/// This function does **not** implement an mSPRT and provides **no
/// anytime-valid guarantee**. The variance is estimated from the same data
/// (plug-in), the Bernoulli/normal approximation is not exact, and the
/// resulting statistic has not been shown to be a test supermartingale with
/// expectation ≤ 1 under the null. Continuous peeking therefore has no
/// proven false-positive control. The compatibility-calibration test
/// `approximate_sequential_diagnostic_is_calibrated_on_a_peeking_grid`
/// checks ONE simulated grid; it is evidence about that grid, not a proof.
///
/// It is also NOT a promotion warrant: promotion goes through the registered
/// sample/credible-interval gate (`crate::experiments::may_promote_arm`),
/// which never reads this statistic.
pub fn sequential_diagnostic_statistic(
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

/// A stateful APPROXIMATE sequential diagnostic: every call is one "look" at
/// the cumulative data. The boundary lets a human decide when to inspect the
/// evidence; it carries no anytime-valid false-positive guarantee and must
/// never be wired to promotion, stopping or a winner announcement.
#[derive(Debug, Clone)]
pub struct SequentialDiagnosticMonitor {
    alpha: f64,
    tau: f64,
    looks: u64,
}

impl Default for SequentialDiagnosticMonitor {
    fn default() -> Self {
        Self::new(SEQUENTIAL_DIAGNOSTIC_ALPHA, SEQUENTIAL_DIAGNOSTIC_TAU)
    }
}

impl SequentialDiagnosticMonitor {
    pub fn new(alpha: f64, tau: f64) -> Self {
        let alpha = if alpha.is_finite() && alpha > 0.0 && alpha < 1.0 {
            alpha
        } else {
            SEQUENTIAL_DIAGNOSTIC_ALPHA
        };
        let tau = if tau.is_finite() && tau > 0.0 {
            tau
        } else {
            SEQUENTIAL_DIAGNOSTIC_TAU
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

    /// The nominal boundary `1 / alpha` (not an anytime-valid critical value).
    pub fn diagnostic_boundary(&self) -> f64 {
        1.0 / self.alpha
    }

    pub fn observe(
        &mut self,
        control_successes: i64,
        control_n: i64,
        treatment_successes: i64,
        treatment_n: i64,
    ) -> SequentialDiagnosticVerdict {
        self.looks += 1;
        let statistic = sequential_diagnostic_statistic(
            control_successes,
            control_n,
            treatment_successes,
            treatment_n,
            self.tau,
        );
        let diagnostic_boundary = self.diagnostic_boundary();
        SequentialDiagnosticVerdict {
            method: SEQUENTIAL_DIAGNOSTIC_METHOD.to_string(),
            looks: self.looks,
            control_n,
            control_successes,
            treatment_n,
            treatment_successes,
            statistic,
            diagnostic_boundary,
            crosses_boundary: statistic >= diagnostic_boundary,
            interpretation: SEQUENTIAL_DIAGNOSTIC_INTERPRETATION.to_string(),
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
    /// Matured trials pooled over BOTH cohort sources. `primary_rate` uses
    /// this denominator; the two split counters below expose how much of it
    /// is reconstructed.
    pub matured: i64,
    pub successes: i64,
    pub primary_rate: Option<f64>,
    /// Matured trials whose first touch the live path observed.
    pub native_matured: i64,
    pub native_successes: i64,
    /// Matured trials rebuilt by migration 290 (INFERRED first touch).
    pub reconstructed_legacy_matured: i64,
    pub reconstructed_legacy_successes: i64,
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
    /// APPROXIMATE sequential diagnostic (NOT anytime-valid, NOT a promotion
    /// warrant); see [`SequentialDiagnosticVerdict`].
    pub sequential_diagnostic: SequentialDiagnosticVerdict,
    pub holdout: Vec<SegmentLift>,
    pub ope: Vec<OpeEstimate>,
    /// Native-versus-reconstructed split of the trial ledger. Dashboards and
    /// API consumers MUST surface or filter this: a reconstructed first touch
    /// is inferred, not observed.
    pub cohort: CohortProvenance,
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
        "SELECT variant, cohort_source, \
                COUNT(*) FILTER (WHERE matured_at IS NOT NULL)::bigint AS matured, \
                COUNT(*) FILTER (WHERE matured_at IS NOT NULL AND success)::bigint AS successes \
         FROM sales_experiment_contact_trials \
         WHERE tenant_id = $1 AND experiment_id = $2 \
           AND primary_metric = $3 AND primary_metric_version = $4 \
         GROUP BY variant, cohort_source",
    )
    .bind(tenant_id)
    .bind(experiment.id)
    .bind(&primary.metric_key)
    .bind(primary.version)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    /// Per-arm trial counts, split by provenance. Any provenance other than
    /// the literal `native` is counted as reconstructed (fail-safe: an
    /// unknown source never reads as an observed first touch).
    #[derive(Debug, Clone, Copy, Default)]
    struct TrialCounts {
        matured: i64,
        successes: i64,
        native_matured: i64,
        native_successes: i64,
        reconstructed_legacy_matured: i64,
        reconstructed_legacy_successes: i64,
    }

    let mut trial_counts: BTreeMap<String, TrialCounts> = BTreeMap::new();
    for row in trial_rows {
        let variant: String = row
            .try_get("variant")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let cohort_source: String = row
            .try_get("cohort_source")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let matured: i64 = row
            .try_get("matured")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let successes: i64 = row
            .try_get("successes")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let counts = trial_counts.entry(variant).or_default();
        counts.matured += matured;
        counts.successes += successes;
        if cohort_source == COHORT_SOURCE_NATIVE {
            counts.native_matured += matured;
            counts.native_successes += successes;
        } else {
            counts.reconstructed_legacy_matured += matured;
            counts.reconstructed_legacy_successes += successes;
        }
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
        let counts = trial_counts.get(&arm.variant).copied().unwrap_or_default();
        let (north_star_matured, revenue) = revenue_by_variant
            .get(&arm.variant)
            .copied()
            .unwrap_or((0, 0.0));
        arms_out.push(ArmScoreboard {
            variant: arm.variant.clone(),
            is_control: arm.is_control,
            matured: counts.matured,
            successes: counts.successes,
            primary_rate: ratio(counts.successes, counts.matured),
            native_matured: counts.native_matured,
            native_successes: counts.native_successes,
            reconstructed_legacy_matured: counts.reconstructed_legacy_matured,
            reconstructed_legacy_successes: counts.reconstructed_legacy_successes,
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

    // APPROXIMATE sequential diagnostic: control vs the best challenger by
    // observed primary rate. The verdict is an inspection aid, never a
    // promotion gate.
    let mut monitor = SequentialDiagnosticMonitor::default();
    let sequential_diagnostic = match control {
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
    let cohort = cohort_provenance(db, tenant_id, experiment.id).await?;
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
        sequential_diagnostic,
        holdout,
        ope,
        cohort,
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

    fn logged(arm: &str, propensity: f64, reward: f64) -> LoggedDecision {
        LoggedDecision {
            arm: arm.to_string(),
            propensity,
            reward,
            propensity_wins: None,
            propensity_draws: None,
            propensity_undersampled: false,
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
            decisions.push(logged(arm, 0.5, reward));
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

        // The diagnostics are populated for each arm.
        let diagnostics = ope_diagnostics(&decisions, "a");
        assert_eq!(diagnostics.valid_decisions, 4_000);
        assert!(diagnostics.arm_decisions > 0);
        assert_eq!(diagnostics.max_inverse_weight, 2.0);
        assert_eq!(diagnostics.p95_inverse_weight, Some(2.0));
        assert_eq!(
            diagnostics.effective_sample_size,
            diagnostics.arm_decisions as f64
        );
        assert!(!diagnostics.clipping_sensitive);

        // A deterministic log: propensity 1.0, reward 2.0 → both estimators
        // return 2.0 exactly.
        let deterministic = vec![logged("b", 1.0, 2.0)];
        assert_eq!(ips(&deterministic, "b"), Some(2.0));
        assert_eq!(snips(&deterministic, "b"), Some(2.0));

        // Honesty: an invalid propensity is dropped, and an arm with no valid
        // decision has NO estimate (not zero).
        let invalid = vec![logged("a", 0.0, 1.0), logged("a", f64::NAN, 1.0)];
        assert_eq!(ips(&invalid, "a"), None);
        assert_eq!(snips(&invalid, "a"), None);
        // IPS averages over every valid decision, so a target arm that was
        // never logged has an honest 0.0; SNIPS has no weight and returns
        // None (no self-normalised estimate exists).
        assert_eq!(ips(&deterministic, "missing"), Some(0.0));
        assert_eq!(snips(&deterministic, "missing"), None);
    }

    #[test]
    fn ope_diagnostics_expose_weight_distribution_ess_and_clipping_sensitivity() {
        // A well-behaved log: 100 decisions, 50 for the target arm at p=0.5.
        // Every inverse weight is 2, so ESS = 50 and clipping never bites.
        let stable: Vec<LoggedDecision> = (0..100)
            .map(|index| {
                if index % 2 == 0 {
                    logged("a", 0.5, if index % 10 == 0 { 1.0 } else { 0.0 })
                } else {
                    logged("b", 0.5, 0.0)
                }
            })
            .collect();
        let diagnostics = ope_diagnostics(&stable, "a");
        assert_eq!(diagnostics.valid_decisions, 100);
        assert_eq!(diagnostics.arm_decisions, 50);
        assert_eq!(diagnostics.max_inverse_weight, 2.0);
        assert_eq!(diagnostics.p95_inverse_weight, Some(2.0));
        assert_eq!(diagnostics.effective_sample_size, 50.0);
        assert_eq!(diagnostics.ips_clipped, ips(&stable, "a"));
        assert_eq!(diagnostics.ips_clipped_half, ips(&stable, "a"));
        assert!(!diagnostics.clipping_sensitive);
        assert_eq!(diagnostics.min_propensity_wins, None);

        // One rare-arm decision at p=0.001 dominates unclipped IPS but is
        // bounded by the clip, and the conclusion changes with the clip: the
        // diagnostics must say so.
        let mut skewed: Vec<LoggedDecision> = (0..99).map(|_| logged("b", 0.5, 0.0)).collect();
        skewed.push(logged("a", 0.001, 1.0));
        let unclipped = ips(&skewed, "a").expect("estimate");
        assert!((unclipped - 10.0).abs() < 1e-9, "{unclipped}");
        let diagnostics = ope_diagnostics(&skewed, "a");
        assert_eq!(diagnostics.max_inverse_weight, 1_000.0);
        assert_eq!(diagnostics.p95_inverse_weight, Some(1_000.0));
        assert_eq!(diagnostics.effective_sample_size, 1.0);
        assert!((diagnostics.ips_clipped.unwrap() - 0.1).abs() < 1e-9);
        assert!((diagnostics.ips_clipped_half.unwrap() - 0.05).abs() < 1e-9);
        assert!(diagnostics.clipping_sensitive);

        // A 0-win Monte-Carlo propensity arrives at the epsilon floor and
        // carries the under-sampled flag into the diagnostics.
        let floored = vec![LoggedDecision {
            arm: "a".into(),
            propensity: crate::experiments::PROPENSITY_FLOOR_EPSILON,
            reward: 1.0,
            propensity_wins: Some(0),
            propensity_draws: Some(2_000),
            propensity_undersampled: true,
        }];
        let diagnostics = ope_diagnostics(&floored, "a");
        assert_eq!(diagnostics.undersampled_decisions, 1);
        assert_eq!(diagnostics.min_propensity_wins, Some(0));
        assert!(diagnostics.max_inverse_weight.is_finite());
        assert_eq!(diagnostics.max_inverse_weight, 10_000.0);
        // The floored propensity is usable: IPS returns a finite estimate
        // instead of dividing by zero.
        let estimate = ips(&floored, "a").expect("a valid bounded estimate");
        assert!(estimate.is_finite() && estimate > 0.0);
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
    fn sequential_diagnostic_flags_a_large_effect_and_is_quiet_under_the_null() {
        // A large effect (10% vs 30% over 1,000 per arm) crosses the nominal
        // boundary. The verdict says "crosses", never "reject": there is no
        // Type-I guarantee behind the line.
        let stat =
            sequential_diagnostic_statistic(100, 1_000, 300, 1_000, SEQUENTIAL_DIAGNOSTIC_TAU);
        assert!(stat >= SEQUENTIAL_DIAGNOSTIC_BOUNDARY, "statistic {stat}");
        let mut monitor = SequentialDiagnosticMonitor::default();
        let verdict = monitor.observe(100, 1_000, 300, 1_000);
        assert!(verdict.crosses_boundary, "{verdict:?}");
        assert_eq!(verdict.diagnostic_boundary, 20.0);
        assert_eq!(verdict.looks, 1);

        // No difference: the statistic is the mixture normalisation
        // sqrt(v / (v + tau²)) < 1, far below the boundary.
        let null =
            sequential_diagnostic_statistic(100, 1_000, 100, 1_000, SEQUENTIAL_DIAGNOSTIC_TAU);
        let variance: f64 = 0.1 * 0.9 / 1_000.0 + 0.1 * 0.9 / 1_000.0;
        let expected =
            (variance / (variance + SEQUENTIAL_DIAGNOSTIC_TAU * SEQUENTIAL_DIAGNOSTIC_TAU)).sqrt();
        assert!((null - expected).abs() < 1e-9, "{null} vs {expected}");
        assert!(null < SEQUENTIAL_DIAGNOSTIC_BOUNDARY);
        // Hostile inputs are quiet, never NaN/infinite.
        assert_eq!(
            sequential_diagnostic_statistic(1, 0, 1, 0, SEQUENTIAL_DIAGNOSTIC_TAU),
            0.0
        );
        assert_eq!(
            sequential_diagnostic_statistic(2, 1, 1, 1, SEQUENTIAL_DIAGNOSTIC_TAU),
            0.0
        );
        assert_eq!(sequential_diagnostic_statistic(1, 10, 2, 10, f64::NAN), 0.0);
    }

    /// The public label and the shipped disclaimer must never claim
    /// anytime validity or promotion authority.
    #[test]
    fn sequential_diagnostic_names_its_limits_in_every_verdict() {
        assert_eq!(
            SEQUENTIAL_DIAGNOSTIC_METHOD,
            "approximate_normal_sequential_diagnostic"
        );
        // The documented boundary is exactly 1/alpha; the monitor computes it
        // the same way, so the constant can never drift from the level.
        assert_eq!(
            SEQUENTIAL_DIAGNOSTIC_BOUNDARY,
            1.0 / SEQUENTIAL_DIAGNOSTIC_ALPHA
        );
        let verdict = SequentialDiagnosticMonitor::default().observe(100, 1_000, 300, 1_000);
        assert_eq!(verdict.method, SEQUENTIAL_DIAGNOSTIC_METHOD);
        let interpretation = verdict.interpretation.to_lowercase();
        assert!(
            interpretation.contains("not anytime-valid"),
            "{interpretation}"
        );
        assert!(
            interpretation.contains("not an msprt"),
            "the disclaimer must explicitly disown the mSPRT name: {interpretation}"
        );
        assert!(
            interpretation.contains("not a promotion warrant"),
            "{interpretation}"
        );
    }

    /// CALIBRATION CHECK of the approximation, NOT a validity proof.
    ///
    /// What it does: simulates 500 null experiments (both arms Bernoulli
    /// 0.1), peeks after every 10 contacts per arm up to 200 per arm, and
    /// reports the fraction of runs that ever cross the nominal boundary on
    /// THIS one grid.
    ///
    /// What it does NOT do: it does not establish anytime validity or an
    /// mSPRT property. The variance is plug-in, the normal approximation is
    /// inexact, and no test-supermartingale argument backs the boundary. A
    /// pass here shows the approximation is roughly calibrated for this
    /// effect size, sample grid and peeking cadence, nothing more. Other
    /// regimes (tiny n, rates near 0/1, continuous peeking) can behave
    /// differently, so the diagnostic is never a promotion warrant.
    #[test]
    fn approximate_sequential_diagnostic_is_calibrated_on_a_peeking_grid() {
        let mut rng = StdRng::seed_from_u64(7);
        let runs = 500usize;
        let look_every = 10usize;
        let max_per_arm = 200usize;
        let mut crossings = 0usize;
        for _ in 0..runs {
            let mut monitor = SequentialDiagnosticMonitor::default();
            let mut control_successes = 0i64;
            let mut treatment_successes = 0i64;
            let mut crossed = false;
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
                if verdict.crosses_boundary {
                    crossed = true;
                    break;
                }
            }
            if crossed {
                crossings += 1;
            }
        }
        let rate = crossings as f64 / runs as f64;
        assert!(
            rate <= SEQUENTIAL_DIAGNOSTIC_ALPHA + 0.02,
            "on this peeking grid the approximation should not flag more than ~alpha of null \
             runs; observed {rate}"
        );
    }

    /// A true effect still flags early under the same peeking: the
    /// diagnostic is not vacuous (sensitivity, not validity).
    #[test]
    fn sequential_diagnostic_is_sensitive_to_a_planted_effect() {
        let mut rng = StdRng::seed_from_u64(11);
        let runs = 200usize;
        let mut flagged = 0usize;
        for _ in 0..runs {
            let mut monitor = SequentialDiagnosticMonitor::default();
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
                    .crosses_boundary
                {
                    hit = true;
                    break;
                }
            }
            if hit {
                flagged += 1;
            }
        }
        let sensitivity = flagged as f64 / runs as f64;
        assert!(
            sensitivity > 0.8,
            "the diagnostic must remain sensitive to a real effect: {sensitivity}"
        );
    }

    // -- Live DB: cohort provenance and holdout membership -----------------

    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    async fn experiment_with_two_arms(pool: &PgPool, label: &str) -> (String, String, Uuid) {
        let tenant = crate::test_db::unique_test_tenant(label);
        let key = format!("{label}-{}", Uuid::new_v4().simple());
        let engine = ExperimentEngine::new(pool.clone());
        let experiment_id = engine
            .ensure_experiment(
                &tenant,
                &key,
                "Scoreboard fixture",
                &serde_json::json!({ "dimensions": ["icp_segment"] }),
                &serde_json::json!({}),
            )
            .await
            .expect("ensure experiment");
        engine
            .ensure_arms(
                &tenant,
                experiment_id,
                &[
                    crate::experiments::ArmSpec::control("control"),
                    crate::experiments::ArmSpec::new("challenger"),
                ],
            )
            .await
            .expect("ensure arms");
        engine
            .set_status(
                &tenant,
                experiment_id,
                crate::experiments::ExperimentStatus::Running,
            )
            .await
            .expect("running");
        (tenant, key, experiment_id)
    }

    /// Item 29: a new trial defaults to `native`, a migration-290-shaped row
    /// is labeled `reconstructed_legacy`, the scoreboard query SEPARATES the
    /// two (per arm and in the top-level provenance), and an unknown source
    /// is rejected by the CHECK.
    #[tokio::test]
    async fn cohort_provenance_separates_reconstructed_from_native_trials() {
        let Some(pool) = live_pool("scoreboard_cohort").await else {
            return;
        };
        let (tenant, key, experiment_id) = experiment_with_two_arms(&pool, "sb-cohort").await;
        let now = Utc::now();
        let first_touch = now - ChronoDuration::days(20);
        let matured = now - ChronoDuration::days(6);

        // A new trial written WITHOUT cohort_source: the column default must
        // make it native.
        let default_source: String = sqlx::query_scalar(
            "INSERT INTO sales_experiment_contact_trials \
                 (tenant_id, experiment_id, variant, contact_id, segment, primary_metric, \
                  primary_metric_version, first_touch_at, matures_at, success, matured_at) \
             VALUES ($1, $2, 'control', $3, 'saas', 'positive_reply_or_meeting_14d', 1, $4, $5, \
                     FALSE, $5) \
             RETURNING cohort_source",
        )
        .bind(&tenant)
        .bind(experiment_id)
        .bind(Uuid::new_v4())
        .bind(first_touch)
        .bind(matured)
        .fetch_one(&pool)
        .await
        .expect("insert native trial");
        assert_eq!(default_source, COHORT_SOURCE_NATIVE);

        // A reconstructed row, exactly what migration 290 produced: the
        // inferred first touch, success already frozen.
        let reconstructed_source: String = sqlx::query_scalar(
            "INSERT INTO sales_experiment_contact_trials \
                 (tenant_id, experiment_id, variant, contact_id, segment, primary_metric, \
                  primary_metric_version, first_touch_at, matures_at, success, matured_at, \
                  cohort_source) \
             VALUES ($1, $2, 'challenger', $3, 'saas', 'positive_reply_or_meeting_14d', 1, $4, \
                     $5, TRUE, $5, 'reconstructed_legacy') \
             RETURNING cohort_source",
        )
        .bind(&tenant)
        .bind(experiment_id)
        .bind(Uuid::new_v4())
        .bind(first_touch)
        .bind(matured)
        .fetch_one(&pool)
        .await
        .expect("insert reconstructed trial");
        assert_eq!(reconstructed_source, COHORT_SOURCE_RECONSTRUCTED_LEGACY);

        // The CHECK refuses an invented provenance instead of letting it
        // pass as native.
        let invalid = sqlx::query(
            "INSERT INTO sales_experiment_contact_trials \
                 (tenant_id, experiment_id, variant, contact_id, segment, primary_metric, \
                  primary_metric_version, first_touch_at, matures_at, cohort_source) \
             VALUES ($1, $2, 'control', $3, 'saas', 'positive_reply_or_meeting_14d', 1, $4, $5, \
                     'invented')",
        )
        .bind(&tenant)
        .bind(experiment_id)
        .bind(Uuid::new_v4())
        .bind(first_touch)
        .bind(matured)
        .execute(&pool)
        .await;
        assert!(invalid.is_err(), "the cohort_source CHECK must reject it");

        let provenance = cohort_provenance(&pool, &tenant, experiment_id)
            .await
            .expect("provenance");
        assert_eq!(provenance.native_trials, 1);
        assert_eq!(provenance.reconstructed_legacy_trials, 1);
        assert!(provenance.mixed);
        assert_eq!(provenance.label, "mixed");
        assert!(provenance.caveat.is_some(), "the caveat must be shipped");

        // The full scoreboard carries the split, both top-level and per arm.
        let scoreboard = compute_scoreboard(&pool, &tenant, &key, now)
            .await
            .expect("scoreboard");
        assert_eq!(scoreboard.cohort.native_trials, 1);
        assert_eq!(scoreboard.cohort.reconstructed_legacy_trials, 1);
        assert!(scoreboard.cohort.mixed);
        let control = scoreboard
            .arms
            .iter()
            .find(|arm| arm.variant == "control")
            .expect("control arm");
        assert_eq!(control.matured, 1);
        assert_eq!(control.native_matured, 1);
        assert_eq!(control.reconstructed_legacy_matured, 0);
        let challenger = scoreboard
            .arms
            .iter()
            .find(|arm| arm.variant == "challenger")
            .expect("challenger arm");
        assert_eq!(challenger.matured, 1);
        assert_eq!(challenger.native_matured, 0);
        assert_eq!(challenger.reconstructed_legacy_matured, 1);
        assert_eq!(challenger.reconstructed_legacy_successes, 1);

        sqlx::query("DELETE FROM sales_experiments WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup experiments");
    }

    /// Item 14: the persisted membership ledger stores BOTH branches, and the
    /// holdout lift counts only `assignment = 'holdout'` rows (a persisted
    /// treatment row is not held out and must not inflate the holdout arm).
    #[tokio::test]
    async fn holdout_lift_counts_only_persisted_holdout_members() {
        let Some(pool) = live_pool("scoreboard_holdout_lift").await else {
            return;
        };
        let (tenant, _key, experiment_id) = experiment_with_two_arms(&pool, "sb-holdout").await;
        let now = Utc::now();
        let assigned_at = now - ChronoDuration::days(20);
        let occurred_at = now - ChronoDuration::days(10);
        let holdout_account = Uuid::new_v4();
        let treatment_account = Uuid::new_v4();
        for (account, company) in [
            (holdout_account, "Holdout Co"),
            (treatment_account, "Treatment Co"),
        ] {
            sqlx::query(
                "INSERT INTO sales_accounts (id, tenant_id, company, domain) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(account)
            .bind(&tenant)
            .bind(company)
            .bind(format!("{}.example.com", Uuid::new_v4().simple()))
            .execute(&pool)
            .await
            .expect("insert account");
        }
        for (account, assignment) in [
            (holdout_account, "holdout"),
            (treatment_account, "treatment"),
        ] {
            sqlx::query(
                "INSERT INTO sales_experiment_holdout_accounts \
                     (experiment_id, tenant_id, account_id, segment, registry_version, \
                      assignment, assigned_at) \
                 VALUES ($1, $2, $3, 'saas', 1, $4, $5)",
            )
            .bind(experiment_id)
            .bind(&tenant)
            .bind(account)
            .bind(assignment)
            .bind(assigned_at)
            .execute(&pool)
            .await
            .expect("insert membership");
        }
        // Both accounts produce an organic success; only the holdout one is
        // held out, so only it belongs in the holdout lift.
        for account in [holdout_account, treatment_account] {
            sqlx::query(
                "INSERT INTO sales_outcomes (id, tenant_id, account_id, outcome, occurred_at) \
                 VALUES (gen_random_uuid(), $1, $2, 'positive_reply', $3)",
            )
            .bind(&tenant)
            .bind(account)
            .bind(occurred_at)
            .execute(&pool)
            .await
            .expect("insert outcome");
        }

        let lift = holdout_lift(&pool, &tenant, experiment_id, now)
            .await
            .expect("holdout lift");
        let saas = lift
            .iter()
            .find(|row| row.segment == "saas")
            .expect("saas segment");
        assert_eq!(
            saas.holdout_matured, 1,
            "only the persisted holdout member is counted, got {saas:?}"
        );
        assert_eq!(saas.holdout_successes, 1);
        assert_eq!(saas.holdout_rate, Some(1.0));

        sqlx::query("DELETE FROM sales_experiments WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup experiments");
        sqlx::query("DELETE FROM sales_accounts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup accounts");
    }
}
