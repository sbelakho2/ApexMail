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
 *     "b<band>a<action>:legit" / ":abuse", EXPIRE 48 h) — at most 24 keys
 *     per scope, no in-process sample arrays;
 *   - bias state: {kiwi:<ns>}:cal:state:<scope> (hash, fields bias/ts) —
 *     written atomically by the bias script (read prev -> rate-clamp ->
 *     write), bounding how fast the bias may move per minute;
 *   - receipts: {kiwi:<ns>}:cal:receipt:<decision_id> (JSON string with
 *     scope/band/action, EXPIRE 300 s), consumed once via GETDEL — lets a
 *     later confirmed outcome be recorded against the ORIGINAL decision's
 *     scope/band/action.
 *
 * biasForScope() never returns a nonzero bias below the store's
 * minSamples threshold and clamps the raw bias to its maxAdjustment; the
 * final bias is rate-limited and cached in-process per scope for 30 s.
 */
interface CalibrationStore
{
    public function record(int $scope, int $band, RiskAction $action, bool $legitimate): void;

    /** Bias adjustment for a scope at `now` (epoch milliseconds). */
    public function biasForScope(int $scope, int $now): int;

    public function recordReceipt(string $decisionId, int $scope, int $band, RiskAction $action): void;

    /** @return array{scope:int, band:int, action:string}|null null when no (or stale) receipt exists */
    public function consumeReceipt(string $decisionId): ?array;
}
