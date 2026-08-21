<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Outcome-feedback calibration store: records whether scored requests were
 * legitimate (post-hoc, e.g. from support flags) and produces a bias
 * adjustment per scope. The bias is added to the raw risk score.
 *
 * The outcome ledger is always on and independent of calibration: every
 * decision gets a pending ledger entry ({"o":"P","scope","hour","score","w"})
 * at registration, either atomically inside register_decision.lua
 * (calibration enabled) or via the store's outcome_register.lua (calibration
 * disabled). ConfirmedLegitimate/ConfirmedAbuse work identically with or
 * without calibration; calibration only observes the outcome state via the
 * canonical confirm.lua / correction.lua scripts. The ledger is the
 * exactly-once authority: pending -> legitimate/abuse once, correction
 * flips it.
 *
 * Implementation is bounded Redis aggregate buckets.
 *   - buckets: {kiwi:<ns>}:cal:<scope>:<hour> (hash, fields
 *     legit_count / legit_score_sum / abuse_count / abuse_score_sum /
 *     sample_total / sample_resolved, exact scores not band-quantized,
 *     written only by the canonical register_decision.lua /
 *     confirm.lua / correction.lua scripts, expire 48 h). At most 24 keys
 *     per scope and no in-process sample arrays. The sample counters live
 *     in the same scope/hour buckets, so scope, window, label population
 *     and resolution population are one cohort.
 *   - bias state: {kiwi:<ns>}:cal:state:<scope> (hash, fields
 *     bias_mp/ts), written atomically by the calibration.lua bias script
 *     (read prev -> rate-clamp -> write), bounding how fast the bias may
 *     move per minute.
 *   - receipts: {kiwi:<ns>}:cal:receipt:<decision_id> (JSON string with
 *     scope/band/action/decision_hour/score/sampled, expire 300 s),
 *     created atomically with the sample denominator and the pending
 *     ledger entry by register_decision.lua (a sample can never be counted
 *     without its receipt), consumed exactly once atomically inside
 *     confirm.lua. The outcome is either fully recorded or not consumed,
 *     with no crash window between reading and incrementing the bucket.
 *   - outcome ledger: {kiwi:<ns>}:cal:ledger:<decision_id> (JSON string
 *     {"o","scope","hour","score","w"}), the always-on exactly-once
 *     authority, written by register_decision.lua (pending) and flipped by
 *     confirm.lua / correction.lua.
 *
 * The resolution gate (random_sample mode) compares the per-scope
 * 24-bucket sample_total/sample_resolved sums, with no singleton
 * counters. Bias adjustment is suspended while sample_total >= min_samples
 * AND sample_resolved < sample_total * minimum_resolution_ratio. The
 * denominator is booked atomically with the receipt by
 * register_decision.lua (sample_total hincrby when the decision was
 * sampled); sample_resolved is incremented by confirm.lua on a status-1
 * confirmation.
 *
 * confirmOutcome() applies the store's sampling mode and returns the
 * shared accepted-outcome status, wire contract with the Rust mirror.
 * Status 0 = nothing consumed (receipt missing / already confirmed /
 * corrupt / unsampled-discard). Status 1 = first confirmation; the exact
 * score was recorded into the scope bucket (+ the sampled-resolved
 * counter in random_sample mode). Status 2 = first confirmation;
 * deliberately unsampled in random_sample mode (consumed, never
 * calibrated, resolved counter untouched).
 * Statuses 1 and 2 both authorize the first-party reputation event exactly
 * once; status 0 must never book one (a webhook retry must never amplify).
 *
 * biasForScope() never returns a nonzero bias below the store's
 * minSamples threshold and clamps the raw bias to its maxAdjustment; the
 * final bias is rate-limited and cached in-process per scope for 30 s.
 * Non-finite guard: the returned bias is always a bounded integer within
 * ±maxAdjustment. A non-finite script reply (NaN/±Inf from corrupted
 * bucket values) maps to +maxAdjustment, fail high, never 0 and never
 * lower-risk-than-max.
 */
interface CalibrationStore
{
    /**
     * Registers the decision atomically via the canonical
     * register_decision.lua: the receipt (pairing the decision with its
     * scope/band/action/decision_hour/score/sampled), the sampled-total
     * denominator (hincrby sample_total in the decision-hour bucket when
     * sampled) and the pending outcome-ledger entry are created in one
     * invocation. A sample can never be counted without its receipt, and
     * a decision always has an outcome-ledger entry regardless of
     * calibration.
     *
     * @return bool true when registered, false when the decision_id is
     *              already registered
     */
    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled, int $decisionHour, float $weight = 1.0): bool;

    /**
     * The assessment-time sampling decision: 'complete'/'weighted' always
     * sample, 'random_sample' samples with samplingProbabilityPpm. Pure,
     * no side effects: the sampled-total denominator is booked atomically
     * with the receipt by recordReceipt()/register_decision.lua.
     */
    public function sample(): bool;

    /**
     * Atomically consumes the decision's receipt (single canonical
     * confirm.lua script: ledger CAS P->L/A exactly once + calibration
     * bucket increment against the decision-time hour), or discards an
     * unsampled receipt in random-sample mode. Returns the shared
     * accepted-outcome status: 0 = nothing consumed, 1 = first
     * confirmation recorded (calibration + resolved counter in
     * random_sample mode), 2 = first confirmation, deliberately unsampled
     * (consumed, no calibration).
     *
     * @throws \InvalidArgumentException when the store's sampling mode is
     *                                   'weighted' and $weight is null
     */
    public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int;

    /**
     * Corrects a confirmed outcome via the canonical
     * correction.lua: flips the ledger L <-> A, reverses the original
     * bucket contribution (exact recorded weight, clamped at zero) and
     * adds the corrected contribution. The corrected outcome is
     * authoritative for future events; if the decision-time bucket already
     * expired, the ledger still flips and the prior ephemeral reputation
     * pressure decays naturally.
     *
     * @return bool true when the correction was applied, false when the
     *              decision is unknown/expired or already carries the
     *              target outcome
     */
    public function correctOutcome(string $decisionId, bool $legitimate, ?float $weight = null): bool;

    /**
     * Per-scope sampling resolution statistics over the 24-bucket window
     * (canonical sampling_metrics.lua): sampledTotal/sampledResolved sums
     * and the resolution ratio (1.0 when nothing was sampled). sampledExpired
     * = max(0, sampledTotal - sampledResolved), an approximation that
     * includes in-flight receipts (booked at decision time, resolved on
     * confirmation).
     *
     * @return array{sampledTotal: int, sampledResolved: int, resolutionRatio: float, sampledExpired: int}
     */
    public function samplingMetrics(int $scope, int $now): array;

    /** Bias adjustment for a scope at `now` (epoch milliseconds). */
    public function biasForScope(int $scope, int $now): int;
}
