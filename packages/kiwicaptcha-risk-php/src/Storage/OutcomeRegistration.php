<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\RiskV2Weights;
use KiwiCaptcha\Risk\RiskWeights;

/**
 * The pending outcome-ledger registration folded into the consolidated
 * assessment call.
 *
 * When present, the consolidated assess_v2.lua invocation registers the
 * decision's pending ledger entry ({"o":"P","scope","hour","score","w":1},
 * SET NX EX under the store's outcome TTL) atomically with the v1
 * observation and the first-seen session tag records. The consolidation
 * makes one round trip instead of the separate outcome_register.lua
 * call. The ledger score is
 * computed inside the script from the exact signals, weights and base
 * risk the engine scores with, so the ledger is byte-identical to the
 * calibration-less registerOutcome() path. When the assessment runs with
 * calibration attached, the engine passes no registration (the
 * calibrator's register_decision.lua stays the sole authority), and when
 * the engine is built without a consolidated store the individual
 * registerOutcome() call stays the path.
 *
 * The decision_id is a fresh random 16-byte hex id (internal handle), the
 * record is keyed by the decision id only and carries the always-on
 * outcome-ledger TTL — no raw client data ever appears in Redis.
 */
final class OutcomeRegistration
{
    public function __construct(
        public readonly string $decisionId,
        public readonly int $decisionHour,
        public readonly int $baseRisk,
        public readonly bool $globalPressureEnabled,
        public readonly bool $honeypotHit,
        public readonly RiskWeights $weights,
        public readonly RiskV2Weights $v2Weights,
    ) {
    }
}
