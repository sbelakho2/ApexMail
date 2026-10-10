<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * The live target-dimension state (change.md 3.2.1): the leaky-bucket
 * authentication-failure counter of one target plus its source and asn
 * spreads (kept separate, never summed). Written by the outcome-bridge
 * path when a failure is reported against a target; compiled into the
 * marks stage's attacked-target record by MarksView::read. Rust mirror:
 * the RiskStateStore target methods over protocol/risk-v1/target_failure.lua.
 */
interface TargetStateStoreInterface
{
    /**
     * Registers one authentication failure against the target dimension:
     * increments the leaky failure counter and PFADDs the failing
     * source/asn spread elements. Returns the updated state.
     *
     * @return array{fails: int, spread_sources: int, spread_asns: int, first_ms: int, last_ms: int}
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function registerTargetFailure(string $targetId, string $source, string $asn): array;

    /**
     * Resets the target's failure counter (step-up completed: the account
     * owner proved themselves, so a legitimate user is not stepped up
     * twice). The spread HLLs keep their history.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function clearTargetFailures(string $targetId): void;

    /**
     * The live target-dimension state of one target.
     *
     * @return array{fails: int, spread_sources: int, spread_asns: int, first_ms: int, last_ms: int}
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function readTargetState(string $targetId): array;
}
