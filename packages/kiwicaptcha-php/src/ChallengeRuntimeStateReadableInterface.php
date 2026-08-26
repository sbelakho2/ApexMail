<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A storage capability: read the challenge's runtime state in ONE
 * snapshot. The state machine (stage-2 recovery, cancellation-aware
 * retirement) must never reconstruct state from two separate reads,
 * `find()` and `consumedState()`, which can race.
 */
interface ChallengeRuntimeStateReadableInterface
{
    public function runtimeState(string $nonce): ChallengeRuntimeState;
}
