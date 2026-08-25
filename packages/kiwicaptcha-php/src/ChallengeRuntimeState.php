<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A single-snapshot runtime state read of a challenge nonce.
 */
final class ChallengeRuntimeState
{
    public function __construct(
        public readonly ChallengeRuntimeStateKind $kind,
        public readonly ?ChallengeRecord $record = null,
        public readonly ?ConsumedRecord $consumed = null,
    ) {
    }
}

