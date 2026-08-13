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
 *     incrementing the bucket).
 *
 * confirmOutcome() applies the store's sampling mode: in random_sample
 * mode a confirmation for a decision that was NOT sampled at assessment
 * time (receipt.sampled == 0) is discarded — the label can never select
 * itself into the calibration population. In complete mode every
 * confirmation is recorded; in weighted mode every confirmation is
 * recorded with the caller-supplied weight (the application supplies the
 * inverse sampling probability).
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
     * sample, 'random_sample' samples with samplingProbabilityPpm.
     */
    public function sample(): bool;

    /**
     * Atomically consumes the decision's receipt (single canonical
     * confirm.lua script) and records the outcome into the CURRENT hour's
     * bucket for the receipt's scope. Returns the scope on success, or
     * null when the receipt is missing / already consumed / discarded by
     * random sampling.
     */
    public function confirmOutcome(string $decisionId, bool $legitimate, ?float $weight = null): ?int;

    /** Bias adjustment for a scope at `now` (epoch milliseconds). */
    public function biasForScope(int $scope, int $now): int;
}
