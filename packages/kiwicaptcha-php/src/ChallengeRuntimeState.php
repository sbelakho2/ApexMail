<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A single-snapshot runtime state read of a challenge nonce.
 */
final readonly class ChallengeRuntimeState
{
    public function __construct(
        public ChallengeRuntimeStateKind $kind,
        public ?ChallengeRecord $record = null,
        public ?ConsumedRecord $consumed = null,
    ) {
    }
}

