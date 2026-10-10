<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\SignalVector;

/**
 * The full reply of one consolidated risk-v2 assessment, as a value object
 * (the PHP mirror of the Rust `AssessV2Reply` struct). It carries the
 * signal vector, the global pressure level, the cooldown deadline, the
 * dedupe verdict, the session's first-seen client-context / trusted-edge
 * TLS tag records and the outcome-ledger registration status of this
 * call.
 *
 * Unlike the lastGlobalLevel()/lastCooldownUntilMs()/lastIsDuplicate()
 * side channels, a reply object is immutable and call-scoped — safe under
 * coroutine runtimes where two assessments may interleave on one store
 * instance.
 */
final class AssessV2Reply
{
    public function __construct(
        public readonly SignalVector $vector,
        public readonly int $globalLevel,
        public readonly int $cooldownUntilMs,
        /** True when the event_id was already applied: the state was NOT
         * mutated and the returned signals are the current ones. */
        public readonly bool $isDuplicate,
        /** The session's first-seen client-context tag (null when none was
         * recorded/presented). */
        public readonly ?string $existingContextTag,
        /** The session's first-seen trusted-edge TLS tag (null when none
         * was recorded/presented). */
        public readonly ?string $existingTlsTag,
        /** True when the pending outcome-ledger entry was created, false
         * when none was requested or the decision is already registered
         * (SET NX collision). */
        public readonly bool $registrationStatus,
        /** Decayed target failure count at assessment time (0 without a target). */
        public readonly int $targetFailures = 0,
        /** Distinct-source spread of target failures (0 without a target).
         * Kept separate from the ASN spread — the two are never summed. */
        public readonly int $targetSpreadSources = 0,
        /** Distinct-ASN spread of target failures (0 without a target). */
        public readonly int $targetSpreadAsns = 0,
    ) {
    }
}
