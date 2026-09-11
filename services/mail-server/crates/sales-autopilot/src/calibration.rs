//! §36 — automatic model calibration.
//!
//! Every probability the system emits is measured against reality. The three
//! fields on [`crate::types::OpportunityScore`] are calibrated here:
//!
//! | metric | prediction | realised event |
//! |---|---|---|
//! | `p_qualified_reply` | `sales_scores.p_qualified_reply` | a `positive_reply`-or-better outcome after the score |
//! | `p_meeting` | `sales_scores.p_meeting` | `meeting_booked` / `meeting_attended` |
//! | `p_paid` | `sales_scores.p_paid` | `paid_subscription` / `retained_mrr` |
//!
//! # The contract
//!
//! **A 70% meeting probability asserted for 100 similar opportunities must
//! show ~70 realised meetings.** A perfectly calibrated synthetic series
//! therefore yields `brier_score` near its theoretical minimum and
//! `|mean_predicted − observed_rate|` near zero; a systematically
//! overconfident series is flagged `overconfident: true`. If an uncalibrated
//! probability were undetectable, the calibration module would be pointless —
//! detecting it is the whole job.
//!
//! * Brier score: `mean((p − y)²)`, lower is better.
//! * Log loss: `−mean(y·ln p + (1−y)·ln(1−p))`, with `p` clamped away from
//!   `0`/`1` by [`LOG_LOSS_EPSILON`] so a single confident mistake is finite
//!   but enormous rather than `inf`.
//! * `overconfident` is set when the mean prediction exceeds the observed rate
//!   by more than [`OVERCONFIDENCE_TOLERANCE`] over at least
//!   [`MIN_N_FOR_OVERCONFIDENCE`] observations, or when any bin with at least
//!   [`MIN_N_FOR_OVERCONFIDENCE`] observations is overconfident by more than
//!   [`BIN_OVERCONFIDENCE_TOLERANCE`]. The bin test catches local drift a
//!   global mean can hide.
//!
//! [`calibration`] is a pure function of `(prediction, outcome)` pairs, so the
//! whole metric layer is unit-testable without a database. [`calibrate`] is
//! the database read that joins `sales_scores` (the prediction, carrying
//! `scoring_version`) to `sales_outcomes` (the realisation).
//!
//! Promotions are gated on calibration through [`may_promote`]: an
//! uncalibrated model may not become production, no matter how good its
//! ranking metrics look.

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::attribution::AttributionWindow;
use crate::types::SalesError;

/// Number of equal-width probability bins in a report.
pub const BIN_COUNT: usize = 10;

/// Prediction above which an arm/system is considered overconfident, as a
/// rate difference.
pub const OVERCONFIDENCE_TOLERANCE: f64 = 0.05;

/// Bin-level rate difference above which a single bin is overconfident.
pub const BIN_OVERCONFIDENCE_TOLERANCE: f64 = 0.15;

/// Minimum observations before overconfidence is claimed (small samples cannot
/// support the claim).
pub const MIN_N_FOR_OVERCONFIDENCE: i64 = 30;

/// Minimum segment observations before drift is called significant.
pub const MIN_N_FOR_SEGMENT_DRIFT: i64 = 30;

/// Segment drift magnitude at which the segment is flagged.
pub const SEGMENT_DRIFT_TOLERANCE: f64 = 0.10;

/// Log-loss probability clamp: `p` is kept in `[ε, 1−ε]` so a confidently
/// wrong prediction is finite.
pub const LOG_LOSS_EPSILON: f64 = 1e-12;

/// Metric names emitted by [`calibrate`].
pub const METRIC_QUALIFIED_REPLY: &str = "p_qualified_reply";
pub const METRIC_MEETING: &str = "p_meeting";
pub const METRIC_PAID: &str = "p_paid";

/// One equal-width calibration bin (`[lower, upper)`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationBin {
    pub lower: f64,
    pub upper: f64,
    pub n: i64,
    pub mean_predicted: f64,
    pub observed_rate: f64,
}

/// The calibration report for one probability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationReport {
    pub metric: String,
    pub n: i64,
    pub mean_predicted: f64,
    pub observed_rate: f64,
    pub brier_score: f64,
    pub log_loss: f64,
    pub bins: Vec<CalibrationBin>,
    pub overconfident: bool,
}

impl CalibrationReport {
    /// `|mean_predicted − observed_rate|`, the headline miscalibration.
    pub fn mean_gap(&self) -> f64 {
        (self.mean_predicted - self.observed_rate).abs()
    }
}

fn sanitize_probability(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        // A non-finite prediction fails closed to 0.0: it is scored as a
        // confident-negative, which the operator will see in the Brier score.
        0.0
    }
}

/// Pure calibration over `(predicted probability, realised boolean)` pairs.
///
/// Empty input yields a report with `n = 0`, zero scores and no bins.
/// Non-finite predictions are sanitised to `0.0` and out-of-range
/// probabilities are clamped, so hostile rows cannot produce a NaN report.
pub fn calibration(observations: &[(f64, bool)]) -> CalibrationReport {
    let n = observations.len() as i64;
    if observations.is_empty() {
        return CalibrationReport {
            metric: String::new(),
            n: 0,
            mean_predicted: 0.0,
            observed_rate: 0.0,
            brier_score: 0.0,
            log_loss: 0.0,
            bins: Vec::new(),
            overconfident: false,
        };
    }

    let mut sum_predicted = 0.0f64;
    let mut successes = 0i64;
    let mut brier = 0.0f64;
    let mut log_loss = 0.0f64;

    let mut bins: Vec<CalibrationBin> = (0..BIN_COUNT)
        .map(|index| {
            let width = 1.0 / BIN_COUNT as f64;
            CalibrationBin {
                lower: index as f64 * width,
                upper: (index + 1) as f64 * width,
                n: 0,
                mean_predicted: 0.0,
                observed_rate: 0.0,
            }
        })
        .collect();
    let mut bin_predicted = [0.0f64; BIN_COUNT];
    let mut bin_successes = [0i64; BIN_COUNT];

    for (predicted, realised) in observations {
        let p = sanitize_probability(*predicted);
        let y = if *realised { 1.0 } else { 0.0 };
        sum_predicted += p;
        if *realised {
            successes += 1;
        }
        brier += (p - y).powi(2);
        let clamped = p.clamp(LOG_LOSS_EPSILON, 1.0 - LOG_LOSS_EPSILON);
        log_loss -= y * clamped.ln() + (1.0 - y) * (1.0 - clamped).ln();

        // `p == 1.0` belongs to the last bin, everything else floors.
        let index = ((p * BIN_COUNT as f64).floor() as usize).min(BIN_COUNT - 1);
        bins[index].n += 1;
        bin_predicted[index] += p;
        if *realised {
            bin_successes[index] += 1;
        }
    }

    let mean_predicted = sum_predicted / n as f64;
    let observed_rate = successes as f64 / n as f64;
    for (index, bin) in bins.iter_mut().enumerate() {
        if bin.n > 0 {
            bin.mean_predicted = bin_predicted[index] / bin.n as f64;
            bin.observed_rate = bin_successes[index] as f64 / bin.n as f64;
        }
    }

    let global_overconfident =
        n >= MIN_N_FOR_OVERCONFIDENCE && mean_predicted - observed_rate > OVERCONFIDENCE_TOLERANCE;
    let bin_overconfident = bins.iter().any(|bin| {
        bin.n >= MIN_N_FOR_OVERCONFIDENCE
            && bin.mean_predicted - bin.observed_rate > BIN_OVERCONFIDENCE_TOLERANCE
    });

    CalibrationReport {
        metric: String::new(),
        n,
        mean_predicted,
        observed_rate,
        brier_score: brier / n as f64,
        log_loss: log_loss / n as f64,
        bins,
        overconfident: global_overconfident || bin_overconfident,
    }
}

/// Precision and recall for a binary reply classifier.
///
/// Input pairs are `(predicted_positive, actually_positive)`.
/// `precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`; a zero
/// denominator yields `0.0` (documented, never NaN).
pub fn precision_recall(observations: &[(bool, bool)]) -> (f64, f64) {
    let mut true_positive = 0i64;
    let mut false_positive = 0i64;
    let mut false_negative = 0i64;
    for (predicted, actual) in observations {
        match (*predicted, *actual) {
            (true, true) => true_positive += 1,
            (true, false) => false_positive += 1,
            (false, true) => false_negative += 1,
            (false, false) => {}
        }
    }
    let precision = if true_positive + false_positive == 0 {
        0.0
    } else {
        true_positive as f64 / (true_positive + false_positive) as f64
    };
    let recall = if true_positive + false_negative == 0 {
        0.0
    } else {
        true_positive as f64 / (true_positive + false_negative) as f64
    };
    (precision, recall)
}

/// Segment-level drift: how far a segment's observed rate sits from the model's
/// prediction for that segment. `significant` requires at least
/// [`MIN_N_FOR_SEGMENT_DRIFT`] observations and a drift of at least
/// [`SEGMENT_DRIFT_TOLERANCE`]; `observed_rate` is `None` when `n <= 0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentDrift {
    pub predicted_rate: f64,
    pub observed_rate: Option<f64>,
    pub drift: Option<f64>,
    pub n: i64,
    pub significant: bool,
}

/// Compare a segment's observed rate to the model's prediction for it.
pub fn segment_drift(predicted_rate: f64, successes: i64, n: i64) -> SegmentDrift {
    let predicted_rate = sanitize_probability(predicted_rate);
    if n <= 0 {
        return SegmentDrift {
            predicted_rate,
            observed_rate: None,
            drift: None,
            n: n.max(0),
            significant: false,
        };
    }
    let successes = successes.clamp(0, n);
    let observed_rate = successes as f64 / n as f64;
    let drift = observed_rate - predicted_rate;
    SegmentDrift {
        predicted_rate,
        observed_rate: Some(observed_rate),
        drift: Some(drift),
        n,
        significant: n >= MIN_N_FOR_SEGMENT_DRIFT && drift.abs() >= SEGMENT_DRIFT_TOLERANCE,
    }
}

/// Promotion gate: a metric may promote a model only when it has at least
/// `min_n` observations, its Brier score is at most `max_brier`, and it is not
/// flagged overconfident.
pub fn may_promote(report: &CalibrationReport, min_n: i64, max_brier: f64) -> bool {
    report.n >= min_n
        && report.brier_score.is_finite()
        && report.brier_score <= max_brier
        && !report.overconfident
}

/// The realisation predicates per metric. These are the exact outcome sets the
/// model is claiming to predict (migration 200_sales_autopilot_v2_unification.
/// sql:768-771).
const QUALIFIED_REPLY_OUTCOMES: &str =
    "'positive_reply', 'meeting_booked', 'meeting_attended', 'trial', 'paid_subscription', 'retained_mrr'";
const MEETING_OUTCOMES: &str = "'meeting_booked', 'meeting_attended'";
const PAID_OUTCOMES: &str = "'paid_subscription', 'retained_mrr'";

/// How many score rows one calibration run may read.
pub const MAX_CALIBRATION_OBSERVATIONS: i64 = 20_000;

/// Calibrate all three emitted probabilities against realised outcomes.
///
/// Joins each `sales_scores` row computed in the window to any matching
/// `sales_outcomes` row that occurred **after** the score (and before the
/// window end). A score row with no later outcome is a negative example, which
/// is the honest reading: the model predicted a probability and the event did
/// not happen in the observation window.
///
/// The per-metric report's `metric` field is set to [`METRIC_QUALIFIED_REPLY`],
/// [`METRIC_MEETING`] or [`METRIC_PAID`].
pub async fn calibrate(
    db: &PgPool,
    tenant_id: &str,
    window: AttributionWindow,
) -> Result<Vec<CalibrationReport>, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    let mut reports = Vec::with_capacity(3);
    for (metric, column, outcomes) in [
        (
            METRIC_QUALIFIED_REPLY,
            "p_qualified_reply",
            QUALIFIED_REPLY_OUTCOMES,
        ),
        (METRIC_MEETING, "p_meeting", MEETING_OUTCOMES),
        (METRIC_PAID, "p_paid", PAID_OUTCOMES),
    ] {
        let observations = load_observations(db, tenant_id, &window, column, outcomes).await?;
        let mut report = calibration(&observations);
        report.metric = metric.to_string();
        reports.push(report);
    }
    Ok(reports)
}

async fn load_observations(
    db: &PgPool,
    tenant_id: &str,
    window: &AttributionWindow,
    column: &str,
    outcomes: &str,
) -> Result<Vec<(f64, bool)>, SalesError> {
    let sql = format!(
        "SELECT s.{column}::float8 AS p, \
                EXISTS ( \
                    SELECT 1 FROM sales_outcomes o \
                    WHERE o.tenant_id = s.tenant_id \
                      AND o.account_id = s.account_id \
                      AND (s.contact_id IS NULL OR o.contact_id IS NULL \
                           OR o.contact_id = s.contact_id) \
                      AND o.occurred_at >= s.computed_at \
                      AND o.occurred_at < $3 \
                      AND o.outcome IN ({outcomes}) \
                ) AS realised \
         FROM sales_scores s \
         WHERE s.tenant_id = $1 AND s.computed_at >= $2 AND s.computed_at < $3 \
         ORDER BY s.computed_at DESC \
         LIMIT {MAX_CALIBRATION_OBSERVATIONS}"
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(window.start)
        .bind(window.end)
        .fetch_all(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let mut observations = Vec::with_capacity(rows.len());
    for row in rows {
        let p: f64 = row
            .try_get("p")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        let realised: bool = row
            .try_get("realised")
            .map_err(|error| SalesError::Database(error.to_string()))?;
        observations.push((p, realised));
    }
    Ok(observations)
}

/// Convenience: the observation window from two instants.
pub fn window_between(
    start: DateTime<chrono::Utc>,
    end: DateTime<chrono::Utc>,
) -> AttributionWindow {
    AttributionWindow::new(start, end)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// THE CONTRACT: a 70% meeting probability over 100 similar opportunities
    /// must show ~70 realised meetings.
    #[test]
    fn seventy_percent_means_seventy_out_of_a_hundred() {
        let observations: Vec<(f64, bool)> = (0..100).map(|index| (0.7, index < 70)).collect();
        let report = calibration(&observations);
        assert_eq!(report.n, 100);
        assert!((report.mean_predicted - 0.7).abs() < 1e-12);
        assert!((report.observed_rate - 0.7).abs() < 1e-12);
        assert!(!report.overconfident);
        // Theoretical minimum Brier for a constant perfectly calibrated
        // p=0.7 series: 0.7·(0.3)² + 0.3·(0.7)² = 0.21.
        assert!(
            (report.brier_score - 0.21).abs() < 1e-12,
            "brier {} must equal the theoretical minimum 0.21",
            report.brier_score
        );
    }

    #[test]
    fn systematically_overconfident_series_is_flagged() {
        // Predicts 0.95 but only half succeed.
        let observations: Vec<(f64, bool)> = (0..100).map(|index| (0.95, index < 50)).collect();
        let report = calibration(&observations);
        assert!(report.overconfident, "{report:?}");
        assert!(report.mean_predicted - report.observed_rate > OVERCONFIDENCE_TOLERANCE);
        // And the miscalibration is visible in the scores, not just the flag.
        let calibrated: Vec<(f64, bool)> = (0..100).map(|index| (0.5, index < 50)).collect();
        let calibrated_report = calibration(&calibrated);
        assert!(
            report.brier_score > calibrated_report.brier_score,
            "overconfident brier {} must exceed the calibrated {}",
            report.brier_score,
            calibrated_report.brier_score
        );
        assert!(report.log_loss > calibrated_report.log_loss);
    }

    #[test]
    fn perfect_deterministic_predictions_have_zero_brier() {
        let mut observations: Vec<(f64, bool)> = Vec::new();
        for _ in 0..50 {
            observations.push((1.0, true));
        }
        for _ in 0..50 {
            observations.push((0.0, false));
        }
        let report = calibration(&observations);
        assert_eq!(report.brier_score, 0.0);
        // Log loss is clamped by LOG_LOSS_EPSILON, so a deterministic series
        // contributes ~1e-12 rather than exactly 0.
        assert!(report.log_loss < 1e-9, "log loss {}", report.log_loss);
        assert!(!report.overconfident);
    }

    #[test]
    fn local_bin_overconfidence_is_caught_even_when_the_mean_is_fine() {
        // 40 observations: 30 at p=0.1 with 0 successes (underconfident) and
        // 30 at p=0.9 with 0 successes (badly overconfident in that bin).
        let mut observations: Vec<(f64, bool)> = Vec::new();
        for _ in 0..30 {
            observations.push((0.1, false));
        }
        for _ in 0..30 {
            observations.push((0.9, false));
        }
        let report = calibration(&observations);
        // Global mean 0.5 vs observed 0.0 → definitely overconfident.
        assert!(report.overconfident);
        let over = report
            .bins
            .iter()
            .find(|bin| bin.upper > 0.9 && bin.lower >= 0.8)
            .expect("the 0.8-0.9 bin");
        assert_eq!(over.n, 30);
        assert!((over.observed_rate - 0.0).abs() < 1e-12);
    }

    #[test]
    fn empty_and_hostile_inputs_never_produce_nan() {
        let empty = calibration(&[]);
        assert_eq!(empty.n, 0);
        assert!(empty.bins.is_empty());
        assert!(!empty.overconfident);
        assert!(!may_promote(&empty, 1, 1.0));

        let hostile = calibration(&[
            (f64::NAN, true),
            (f64::INFINITY, false),
            (f64::NEG_INFINITY, true),
            (-1.0, true),
            (2.0, false),
        ]);
        assert_eq!(hostile.n, 5);
        assert!(hostile.brier_score.is_finite());
        assert!(hostile.log_loss.is_finite());
        assert!(hostile.mean_predicted.is_finite());
        assert!(hostile.observed_rate.is_finite());
    }

    #[test]
    fn log_loss_matches_the_closed_form() {
        let report = calibration(&[(0.5, true), (0.5, false)]);
        assert!((report.log_loss - std::f64::consts::LN_2).abs() < 1e-12);
        // A confidently wrong prediction is finite but large.
        let report = calibration(&[(1.0, false)]);
        assert!(report.log_loss.is_finite());
        assert!(report.log_loss > 20.0, "{}", report.log_loss);
    }

    #[test]
    fn precision_recall_covers_the_confusion_matrix() {
        assert_eq!(precision_recall(&[]), (0.0, 0.0));
        assert_eq!(precision_recall(&[(true, true)]), (1.0, 1.0));
        assert_eq!(precision_recall(&[(true, false)]), (0.0, 0.0));
        assert_eq!(precision_recall(&[(false, true)]), (0.0, 0.0));
        // TP=1, FP=1, FN=1 → precision 0.5, recall 0.5.
        let mixed = precision_recall(&[(true, true), (true, false), (false, true)]);
        assert!((mixed.0 - 0.5).abs() < 1e-12);
        assert!((mixed.1 - 0.5).abs() < 1e-12);
        // No predicted positives → precision 0 (documented), recall 0.
        let no_predictions = precision_recall(&[(false, true), (false, false)]);
        assert_eq!(no_predictions, (0.0, 0.0));
    }

    #[test]
    fn segment_drift_detects_real_divergence() {
        let none = segment_drift(0.5, 0, 0);
        assert_eq!(none.observed_rate, None);
        assert!(!none.significant);

        let clean = segment_drift(0.5, 50, 100);
        assert!((clean.observed_rate.unwrap() - 0.5).abs() < 1e-12);
        assert!(!clean.significant);

        let drifting = segment_drift(0.5, 20, 100);
        assert!((drifting.drift.unwrap() - (-0.3)).abs() < 1e-12);
        assert!(drifting.significant);

        // Below the sample floor the drift is not called significant.
        let thin = segment_drift(0.5, 2, 10);
        assert!(!thin.significant);
        // Hostile inputs are sanitized.
        let hostile = segment_drift(f64::NAN, -5, -10);
        assert_eq!(hostile.observed_rate, None);
        assert!(!hostile.significant);
    }

    #[test]
    fn may_promote_refuses_a_badly_calibrated_report() {
        let overconfident: Vec<(f64, bool)> = (0..100).map(|index| (0.95, index < 50)).collect();
        let report = calibration(&overconfident);
        assert!(!may_promote(&report, 50, 0.25));

        let calibrated: Vec<(f64, bool)> = (0..100).map(|index| (0.7, index < 70)).collect();
        let report = calibration(&calibrated);
        assert!(may_promote(&report, 50, 0.25));
        // Too few observations.
        assert!(!may_promote(&report, 1_000, 0.25));
        // Brier budget too tight.
        assert!(!may_promote(&report, 50, 0.1));
        // Hostile max_brier.
        assert!(!may_promote(&report, 50, f64::NAN));
    }
}
