//! Campaign A/B experiment execution rules — the ONE deterministic
//! assignment + winner-decision contract shared by the campaign send path
//! (`worker-processors::campaigns`) and the experiment results API
//! (`api-server::routes::campaign_experiments`).
//!
//! # Arm assignment
//!
//! [`AB_SPLIT_SQL`] assigns every un-phased `campaign_recipients` row a
//! 32-bit bucket derived from `md5(campaign_id || ':' || contact_id)`:
//!
//! * `bucket % 10000 < ceil(testPercentage * 10000)` → `phase = 'test'`;
//! * otherwise → `phase = 'holdout'` (held until a winner is declared);
//! * test rows get `arm_index = (bucket / 10000) % arm_count`.
//!
//! The hash keys on `(experiment, recipient)` — never on row order or a
//! generated row id — so a replay, a resend, or a re-expansion of the same
//! audience assigns the SAME arm to the same contact. The persisted
//! `campaign_recipients.ab_bucket` makes the assignment auditable without
//! recomputing the hash.
//!
//! # Winner decision
//!
//! [`decide_winner`] documents and implements the honest rule:
//!
//! 1. **Minimum sample.** Every arm must have at least [`MIN_ARM_TRIALS`]
//!    sent test recipients. Below that the decision is
//!    [`AbVerdict::Refused`] with code `insufficient_sample` naming the arm
//!    and its trial count — the caller must surface that reason, never
//!    declare a leader from an under-powered sample.
//! 2. **Two-proportion z-test.** The leader (highest success rate, ties
//!    broken by lowest arm index) is compared against the runner-up with the
//!    pooled two-proportion z statistic at the two-sided 95% level
//!    ([`Z_CRITICAL`] = 1.96). Below the critical value the decision is
//!    `no_significant_leader` (with the observed z in the reason); at or
//!    above it the leader is declared the winner.
//! 3. Degenerate samples (zero successes everywhere, or every trial a
//!    success) carry no variance: the decision is `no_signal`.
//!
//! The rule is deliberately conservative: refusing to declare beats
//! fabricating significance. A refused experiment can still be concluded by
//! an explicit, audited manual declaration through the API.

/// Minimum sent test recipients every arm needs before [`decide_winner`]
/// will consider declaring a winner.
pub const MIN_ARM_TRIALS: i64 = 30;

/// Two-sided 95% normal critical value used by the two-proportion z-test.
pub const Z_CRITICAL: f64 = 1.96;

/// The deterministic phase/arm assignment for every un-phased recipient of
/// one campaign.
///
/// Bind: `$1` campaign id (UUID), `$2` test percentage (`f64`, the validated
/// 0.1–0.5 window), `$3` arm count (`i64`, 2–4). Only rows with
/// `phase IS NULL` are touched, so re-running is a no-op for already
/// assigned rows (replays keep their original arm). Returns the number of
/// rows assigned.
///
/// The bucket is `md5(campaign_id || ':' || contact_id)` truncated to 32
/// bits: stable per (experiment, recipient), independent of row ordering,
/// audience size, and insertion order.
pub const AB_SPLIT_SQL: &str = "\
WITH scored AS ( \
    SELECT id, \
           ('x' || substr(md5($1::text || ':' || contact_id::text), 1, 8))::bit(32)::bigint AS bucket \
    FROM campaign_recipients \
    WHERE campaign_id = $1 AND phase IS NULL \
) \
UPDATE campaign_recipients cr \
SET phase = CASE \
        WHEN s.bucket % 10000 < CEIL($2 * 10000)::bigint THEN 'test' \
        ELSE 'holdout' \
    END, \
    arm_index = CASE \
        WHEN s.bucket % 10000 < CEIL($2 * 10000)::bigint \
            THEN ((s.bucket / 10000) % $3)::int \
        ELSE NULL \
    END, \
    ab_bucket = s.bucket, \
    updated_at = NOW() \
FROM scored s \
WHERE cr.id = s.id";

/// Refresh `campaign_ab_arms.trials` / `successes` from the append-only
/// events stream for one campaign and return every arm's counters.
///
/// Bind: `$1` campaign id (UUID), `$2` metric event type (`opened` or
/// `clicked`). A trial is a `phase = 'test'` recipient whose send succeeded
/// (`status = 'sent'`); a success is a DISTINCT message of that arm carrying
/// the metric event. The per-arm `updated_at` (the experiment window clock)
/// is deliberately preserved.
///
/// Used by the worker (which also writes the refreshed counters back) — the
/// API's read-only twin is [`AB_OUTCOMES_SELECT_SQL`]; both compute the same
/// numbers and must stay in lockstep.
pub const AB_OUTCOMES_REFRESH_SQL: &str = "\
WITH per_arm AS ( \
    SELECT cr.arm_index AS arm, \
           COUNT(*) FILTER (WHERE cr.status = 'sent') AS trials, \
           COUNT(DISTINCT e.message_id) FILTER (WHERE e.event_type = $2) AS successes \
    FROM campaign_recipients cr \
    LEFT JOIN events e \
      ON e.campaign_id = $1::text \
     AND e.message_id = cr.message_id::text \
    WHERE cr.campaign_id = $1 \
      AND cr.phase = 'test' \
      AND cr.arm_index IS NOT NULL \
    GROUP BY cr.arm_index \
) \
UPDATE campaign_ab_arms a \
SET trials = per_arm.trials, \
    successes = COALESCE(per_arm.successes, 0), \
    updated_at = a.updated_at \
FROM per_arm \
WHERE a.campaign_id = $1 AND a.arm_index = per_arm.arm \
RETURNING a.arm_index, a.trials, a.successes";

/// Read-only twin of [`AB_OUTCOMES_REFRESH_SQL`]: every arm of the campaign
/// with its current trials/successes (arms without test recipients report
/// `0/0`). Bind the same `$1` campaign id and `$2` metric event type.
pub const AB_OUTCOMES_SELECT_SQL: &str = "\
SELECT a.arm_index, \
       COALESCE(per_arm.trials, 0)::bigint, \
       COALESCE(per_arm.successes, 0)::bigint \
FROM campaign_ab_arms a \
LEFT JOIN ( \
    SELECT cr.arm_index AS arm, \
           COUNT(*) FILTER (WHERE cr.status = 'sent') AS trials, \
           COUNT(DISTINCT e.message_id) FILTER (WHERE e.event_type = $2) AS successes \
    FROM campaign_recipients cr \
    LEFT JOIN events e \
      ON e.campaign_id = $1::text \
     AND e.message_id = cr.message_id::text \
    WHERE cr.campaign_id = $1 \
      AND cr.phase = 'test' \
      AND cr.arm_index IS NOT NULL \
    GROUP BY cr.arm_index \
) per_arm ON per_arm.arm = a.arm_index \
WHERE a.campaign_id = $1 \
ORDER BY a.arm_index";

/// One arm's observed outcome inside the test sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArmOutcome {
    pub arm_index: i32,
    pub trials: i64,
    pub successes: i64,
}

impl ArmOutcome {
    /// Success rate over the arm's trials (`0.0` for zero trials — an arm
    /// that sent nothing can never lead).
    pub fn rate(&self) -> f64 {
        if self.trials <= 0 {
            0.0
        } else {
            self.successes as f64 / self.trials as f64
        }
    }
}

/// The outcome of [`decide_winner`].
#[derive(Debug, Clone, PartialEq)]
pub enum AbVerdict {
    /// A statistically significant leader was found.
    Winner {
        /// The winning arm's index.
        arm_index: i32,
        /// The observed two-proportion z statistic (>= [`Z_CRITICAL`]).
        z: f64,
        /// The winning arm's success rate.
        rate: f64,
        /// The runner-up arm (the comparison the z statistic was computed
        /// against).
        runner_up_arm: i32,
        runner_up_rate: f64,
    },
    /// The experiment cannot honestly name a winner yet. `code` is the
    /// stable machine reason; `reason` is the human sentence to surface.
    Refused { code: &'static str, reason: String },
}

impl AbVerdict {
    /// Stable machine code (`winner` / `insufficient_sample` / …).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Winner { .. } => "winner",
            Self::Refused { code, .. } => code,
        }
    }
}

/// Decide the winner from the per-arm outcomes under the documented rule
/// (minimum sample + two-proportion z-test at the two-sided 95% level; see
/// the module docs). Never panics; an empty or single-arm experiment is
/// refused with `insufficient_arms`.
pub fn decide_winner(arms: &[ArmOutcome]) -> AbVerdict {
    if arms.len() < 2 {
        return AbVerdict::Refused {
            code: "insufficient_arms",
            reason: format!(
                "the experiment has {} arm(s); at least 2 are required",
                arms.len()
            ),
        };
    }

    // Minimum sample first: an under-powered arm refuses the whole decision
    // (declaring a winner off 3 sends would be noise, not evidence).
    for arm in arms {
        if arm.trials < MIN_ARM_TRIALS {
            return AbVerdict::Refused {
                code: "insufficient_sample",
                reason: format!(
                    "arm {} has {} sent test recipient(s); {} are required per arm before a \
                     winner can be declared",
                    arm.arm_index, arm.trials, MIN_ARM_TRIALS
                ),
            };
        }
    }

    // Leader by rate, ties broken by lowest arm index (deterministic).
    let mut ordered: Vec<&ArmOutcome> = arms.iter().collect();
    ordered.sort_by(|a, b| {
        b.rate()
            .partial_cmp(&a.rate())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.arm_index.cmp(&b.arm_index))
    });
    let leader = ordered[0];
    let runner_up = ordered[1];

    let leader_rate = leader.rate();
    let runner_up_rate = runner_up.rate();
    let pooled =
        (leader.successes + runner_up.successes) as f64 / (leader.trials + runner_up.trials) as f64;

    // Zero successes everywhere (pooled p = 0) or every trial a success
    // (pooled p = 1) has zero variance: the z statistic is undefined.
    if pooled <= 0.0 {
        return AbVerdict::Refused {
            code: "no_signal",
            reason: "no successes have been recorded on any arm yet".into(),
        };
    }
    if pooled >= 1.0 {
        return AbVerdict::Refused {
            code: "no_signal",
            reason: "every trial succeeded — the arms carry no measurable difference".into(),
        };
    }

    let standard_error =
        (pooled * (1.0 - pooled) * (1.0 / leader.trials as f64 + 1.0 / runner_up.trials as f64))
            .sqrt();
    if !standard_error.is_finite() || standard_error <= 0.0 {
        return AbVerdict::Refused {
            code: "no_signal",
            reason: "the observed outcomes carry no measurable variance".into(),
        };
    }
    let z = (leader_rate - runner_up_rate) / standard_error;

    if !z.is_finite() || z < Z_CRITICAL {
        return AbVerdict::Refused {
            code: "no_significant_leader",
            reason: format!(
                "arm {} leads arm {} ({:.1}% vs {:.1}%) but the difference is not significant \
                 at the two-sided 95% level (z = {:.2}, required >= {:.2})",
                leader.arm_index,
                runner_up.arm_index,
                leader_rate * 100.0,
                runner_up_rate * 100.0,
                if z.is_finite() { z } else { 0.0 },
                Z_CRITICAL
            ),
        };
    }

    AbVerdict::Winner {
        arm_index: leader.arm_index,
        z,
        rate: leader_rate,
        runner_up_arm: runner_up.arm_index,
        runner_up_rate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arm(arm_index: i32, trials: i64, successes: i64) -> ArmOutcome {
        ArmOutcome {
            arm_index,
            trials,
            successes,
        }
    }

    #[test]
    fn refuses_an_experiment_with_fewer_than_two_arms() {
        for arms in [vec![], vec![arm(0, 100, 50)]] {
            let verdict = decide_winner(&arms);
            assert_eq!(verdict.code(), "insufficient_arms");
            assert!(matches!(verdict, AbVerdict::Refused { .. }));
        }
    }

    #[test]
    fn refuses_below_the_minimum_sample_naming_the_short_arm() {
        let verdict = decide_winner(&[arm(0, 300, 75), arm(1, MIN_ARM_TRIALS - 1, 10)]);
        let AbVerdict::Refused { code, reason } = verdict else {
            panic!("an arm below {MIN_ARM_TRIALS} trials must refuse");
        };
        assert_eq!(code, "insufficient_sample");
        assert!(
            reason.contains("arm 1") && reason.contains("29"),
            "the reason must name the short arm and its count: {reason}"
        );
    }

    #[test]
    fn refuses_when_the_leader_is_not_significant() {
        // 20% vs 15% on 300 trials each: z = 1.61 < 1.96.
        let verdict = decide_winner(&[arm(0, 300, 60), arm(1, 300, 45)]);
        let AbVerdict::Refused { code, reason } = verdict else {
            panic!("a 5-point lead on 300 trials is not significant");
        };
        assert_eq!(code, "no_significant_leader");
        assert!(
            reason.contains("arm 0 leads arm 1"),
            "the reason must name the comparison: {reason}"
        );
        assert!(reason.contains("z = 1.61"), "the observed z: {reason}");
    }

    #[test]
    fn declares_a_significant_leader() {
        // 25% vs 15% on 300 trials each: z = 3.06 > 1.96.
        let verdict = decide_winner(&[arm(0, 300, 75), arm(1, 300, 45)]);
        let AbVerdict::Winner {
            arm_index,
            z,
            rate,
            runner_up_arm,
            ..
        } = verdict
        else {
            panic!("a 10-point lead on 300 trials must win");
        };
        assert_eq!(arm_index, 0);
        assert_eq!(runner_up_arm, 1);
        assert!(z > Z_CRITICAL, "z = {z}");
        assert!((rate - 0.25).abs() < 1e-9);
    }

    #[test]
    fn a_larger_lead_needs_less_sample_but_never_below_the_floor() {
        // 40% vs 10% with 40 trials each: z ≈ 3.1 — significant, and 40 is
        // above the 30-trial floor.
        let verdict = decide_winner(&[arm(0, 40, 16), arm(1, 40, 4)]);
        assert!(matches!(verdict, AbVerdict::Winner { arm_index: 0, .. }));

        // The same rates below the floor still refuse.
        let verdict = decide_winner(&[arm(0, 29, 12), arm(1, 29, 3)]);
        assert_eq!(verdict.code(), "insufficient_sample");
    }

    #[test]
    fn all_zero_or_all_one_successes_have_no_signal() {
        assert_eq!(
            decide_winner(&[arm(0, 100, 0), arm(1, 100, 0)]).code(),
            "no_signal"
        );
        assert_eq!(
            decide_winner(&[arm(0, 100, 100), arm(1, 100, 100)]).code(),
            "no_signal"
        );
    }

    #[test]
    fn ties_break_to_the_lowest_arm_index_deterministically() {
        // Equal rates above the floor cannot be significant (z = 0).
        let verdict = decide_winner(&[arm(0, 100, 50), arm(1, 100, 50)]);
        assert_eq!(verdict.code(), "no_significant_leader");
        // Determinism: repeated calls carry the same reason text.
        let again = decide_winner(&[arm(0, 100, 50), arm(1, 100, 50)]);
        assert_eq!(verdict, again);
    }

    #[test]
    fn rate_is_zero_for_untried_arms() {
        assert_eq!(arm(0, 0, 5).rate(), 0.0);
        assert_eq!(arm(0, 4, 1).rate(), 0.25);
    }
}
