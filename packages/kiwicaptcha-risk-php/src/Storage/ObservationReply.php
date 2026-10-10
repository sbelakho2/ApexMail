<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

use KiwiCaptcha\Risk\SignalVector;

/**
 * The full reply of one observation, as a value object (the PHP mirror of
 * the Rust `Observed` struct): the signal vector plus the global pressure
 * level, cooldown deadline and dedupe verdict of this call.
 *
 * Unlike the lastGlobalLevel()/lastCooldownUntilMs()/lastIsDuplicate()
 * side channels, a reply object is immutable and call-scoped — safe under
 * coroutine runtimes where two assessments may interleave on one store
 * instance.
 */
final class ObservationReply
{
    public function __construct(
        public readonly SignalVector $vector,
        public readonly int $globalLevel,
        public readonly int $cooldownUntilMs,
        /** True when the event_id was already applied: the state was NOT
         * mutated and the returned signals are the current ones. */
        public readonly bool $isDuplicate,
    ) {
    }
}
