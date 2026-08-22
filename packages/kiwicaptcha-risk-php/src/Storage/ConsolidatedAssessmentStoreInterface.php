<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\SignalVector;

/**
 * Optional risk-v2 capability of a risk state store: the consolidated
 * assessment call.
 *
 * One atomic script invocation runs the v1 observation and applies the
 * session's first-seen client-context tag + trusted-edge TLS tag records
 * (SET NX, first write wins, session TTL). When a registration is given,
 * it also registers the decision's pending outcome-ledger entry,
 * returning the signal vector, the recorded tag values and the
 * registration status.
 * The engine's assessment path switches to this single call when the
 * store implements the capability: an established risk-v2 session costs
 * one script call instead of the separate tag round trips and the
 * separate outcome registration.
 *
 * This is a separate capability interface so third-party implementations
 * of the 1.x RiskStateStoreInterface keep compiling unchanged: a store
 * without it falls back to the plain observe() plus the individual
 * SessionContextTagStoreInterface/SessionTlsTagStoreInterface calls and
 * the registerOutcome() call, with identical semantics.
 */
interface ConsolidatedAssessmentStoreInterface
{
    /**
     * The consolidated risk-v2 assessment: applies the observation with
     * the exact risk-v1 semantics, records the presented tags
     * first-write-wins under the session TTL and, when $registration is
     * given, registers the pending outcome-ledger entry atomically.
     *
     * $contextTag / $tlsTag are the presented tags of the current request
     * (null/'' = none presented; the corresponding record is untouched and
     * its existing value is reported as null). The engine passes them only
     * when a session pseudonym exists and the tag passes the contract
     * bounds — the records are keyed by the session pseudonym only and
     * stay ephemeral + session-keyed.
     *
     * $registration carries the pending outcome-ledger entry to create
     * (decision id, decision hour, the exact base risk / weights the
     * engine scores with); null skips the registration. The engine passes
     * it only on the calibration-less assessment path (with calibration
     * attached, the calibrator's register_decision.lua is the sole
     * authority).
     *
     * @return array{0: SignalVector, 1: ?string, 2: ?string, 3: bool} the
     *         signal vector, the recorded client-context tag (null when
     *         none recorded/presented), and the recorded TLS tag (null
     *         when none recorded/presented). The registration status is
     *         true when the pending entry was created, false when none
     *         was requested or the decision is already registered.
     * @throws RiskStoreException when the underlying state backend fails
     */
    public function assessV2(RiskObservation $observation, ?string $contextTag, ?string $tlsTag, ?OutcomeRegistration $registration = null): array;
}
