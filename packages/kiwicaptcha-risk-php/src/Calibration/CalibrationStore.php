<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Calibration;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Outcome-feedback calibration store: records whether scored requests were
 * legitimate (post-hoc, e.g. from support flags) and produces a bias
 * adjustment per scope. The bias is added to the raw risk score.
 *
 * Implementation is BOUNDED Redis aggregate buckets:
 *   - buckets: {kiwi:<ns>}:cal:<scope>:<hour> (hash, fields
 *     legit_count / legit_score_sum / abuse_count / abuse_score_sum —
 *     EXACT scores, not band-quantized — written ONLY by the canonical
 *     confirm.lua script, EXPIRE 48 h) — at most 24 keys per scope, no
 *     in-process sample arrays;
 *   - bias state: {kiwi:<ns>}:cal:state:<scope> (hash, fields
 *     bias_mp/ts) — written atomically by the calibration.lua bias script
 *     (read prev -> rate-clamp -> write), bounding how fast the bias may
 *     move per minute;
 *   - receipts: {kiwi:<ns>}:cal:receipt:<decision_id> (JSON string with
 *     scope/band/action/score/sampled, EXPIRE 300 s), consumed EXACTLY
 *     ONCE atomically inside confirm.lua — the outcome is EITHER fully
 *     recorded OR not consumed (no crash window between reading and
 *     incrementing the bucket);
 *   - random-sample resolution counters: {kiwi:<ns>}:cal:sample:total
 *     (assessment-time sampled-decision total; INCR per sampled decision)
 *     and {kiwi:<ns>}:cal:sample:resolved (confirmed sampled outcomes;
 *     INCR by confirm.lua on a status-1 confirmation in random_sample
 *     mode) — the resolution gate suspends bias movement while
 *     total >= min_samples and resolved/total < minimum_resolution_ratio.
 *
 * confirmOutcome() applies the store's sampling mode and returns the
 * SHARED accepted-outcome status (wire contract with the Rust mirror):
 *   0 = nothing consumed (receipt missing / already confirmed / corrupt /
 *      unsampled-discard),
 *   1 = FIRST confirmation; the exact score was recorded into the scope
 *      bucket (+ the sampled-resolved counter in random_sample mode),
 *   2 = FIRST confirmation; deliberately unsampled in random_sample mode
 *      (consumed, never calibrated, resolved counter untouched).
 * Statuses 1 and 2 both authorize the first-party reputation event exactly
 * once; status 0 must never book one (a webhook retry must never amplify).
 *
 * biasForScope() never returns a nonzero bias below the store's
 * minSamples threshold and clamps the raw bias to its maxAdjustment; the
 * final bias is rate-limited and cached in-process per scope for 30 s.
 */
interface CalibrationStore
{
    /**
     * Registers the receipt pairing a decision with its scope/band/action
     * plus the EXACT risk score and the sampling flag captured at
     * assessment time, so a later confirmed outcome is recorded against
     * the ORIGINAL decision's scope bucket.
     */
    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action, int $score, int $sampled): void;

    /**
     * The assessment-time sampling decision: 'complete'/'weighted' always
     * sample, 'random_sample' samples with samplingProbabilityPpm. In
     * random_sample mode a sampled decision ALSO books the namespace-wide
     * sampled-TOTAL counter (the resolution-gate denominator) — one INCR
     * per sampled decision.
     */
    public function sample(): bool;

    /**
     * Assessment-time accounting hook: books a sampled decision into the
     * sampled-TOTAL counter {kiwi:<ns>}:cal:sample:total (in random_sample
     * mode only — the resolution gate applies exclusively to it). Other
     * modes are no-ops.
     */
    public function markSampled(): void;

    /**
     * Atomically consumes the decision's receipt (single canonical
     * confirm.lua script) and records the outcome into the CURRENT hour's
     * bucket for the receipt's scope — or discards an unsampled receipt in
     * random-sample mode. Returns the SHARED accepted-outcome status:
     * 0 = nothing consumed, 1 = FIRST confirmation recorded (calibration +
     * resolved counter in random_sample mode), 2 = FIRST confirmation,
     * deliberately unsampled (consumed, no calibration).
     */
    public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): int;

    /**
     * Reserves the once-only correction slot for a decision: SET NX
     * {kiwi:<ns>}:cal:corrected:<hex(sha256(decisionId))> EX
     * receiptTtlSecs. True = this call WON the slot (the engine may record
     * its compensating event); false = already corrected.
     */
    public function reserveCorrection(string $decisionId): bool;

    /** Bias adjustment for a scope at `now` (epoch milliseconds). */
    public function biasForScope(int $scope, int $now): int;
}
