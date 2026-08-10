<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * An issued challenge, ready to serialize to the widget.
 *
 * Wire shape matches the Rust `IssuedChallenge` exactly so the widget (and the
 * WASM solver) behave identically regardless of the backend language.
 */
final class Challenge
{
    public function __construct(
        public readonly string $nonce,
        public readonly string $challenge,
        public readonly string $salt,
        public readonly PoWAlgorithm $algorithm,
        public readonly int $mKib,
        public readonly int $t,
        public readonly int $p,
        public readonly int $targetBits,
        public readonly int $ttlSecs,
        public readonly int $minDurationMs,
        public readonly string $prefix,
    ) {
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'nonce' => $this->nonce,
            'challenge' => $this->challenge,
            'salt' => $this->salt,
            'algorithm' => $this->algorithm->value,
            'mKib' => $this->mKib,
            't' => $this->t,
            'p' => $this->p,
            'targetBits' => $this->targetBits,
            'ttlSecs' => $this->ttlSecs,
            'minDurationMs' => $this->minDurationMs,
            'prefix' => $this->prefix,
        ];
    }
}
