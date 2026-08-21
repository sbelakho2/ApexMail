<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;

/**
 * Risk state store: atomically applies an observation and returns the
 * resulting SignalVector.
 *
 * The outcome ledger is part of the store contract: the always-on,
 * calibration-independent exactly-once authority for confirmed outcomes
 * (pending -> legitimate/abuse once, correction flips it). Confirmed
 * outcomes work identically with or without calibration; calibration
 * only observes the ledger via the canonical confirm/correction scripts.
 */
interface RiskStateStoreInterface
{
    /**
     * Applies the observation exactly once (event_id dedupe) and returns
     * the current signal vector.
     *
     * A duplicate event_id does NOT apply the state again, but the current
     * signals ARE returned (there is no -1 marker anymore); the store
     * exposes the duplicate flag via lastIsDuplicate() (when present). The
     * engine's degraded path is NOT triggered by a duplicate.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function observe(RiskObservation $observation): SignalVector;

    /**
     * Registers the decision's pending outcome-ledger entry (SET NX EX via
     * the canonical outcome_register.lua): {"o":"P","scope","hour","score","w":1}
     * keyed {kiwi:<ns>}:cal:ledger:<decisionId> with the store's
     * outcomeTtlSecs. Used when calibration is disabled; the engine always
     * registers one ledger entry per decision regardless of calibration.
     *
     * @return bool true when the pending entry was created, false when the
     *              decision is already registered
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool;

    /**
     * Confirms the decision's outcome exactly once (canonical
     * outcome_confirm.lua): pending -> L/A. Returns 1 when this call
     * performed the first confirmation, 0 when the decision is unknown,
     * already confirmed or the ledger is not pending. A webhook retry
     * can never confirm twice.
     *
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function confirmOutcome(string $decisionId, bool $legitimate): int;

    /**
     * Corrects a confirmed outcome (canonical outcome_correct.lua):
     * flips the ledger L <-> A. The corrected outcome is authoritative for
     * future events; ephemeral reputation pressure is left to decay.
     *
     * @return bool true when the ledger was flipped, false when the
     *              decision is unknown/expired or already carries the target
     *              outcome
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function correctOutcome(string $decisionId, bool $legitimate): bool;
}
