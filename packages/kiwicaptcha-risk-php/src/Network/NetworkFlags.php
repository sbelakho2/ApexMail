<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Network;

/**
 * Network classification flags for a source IP.
 *
 * localRiskBucket: 0..255; 255 is the reserved "blocked" bucket.
 */
final class NetworkFlags
{
    public function __construct(
        public readonly bool $reserved = false,
        public readonly bool $knownHosting = false,
        public readonly bool $knownProxy = false,
        public readonly bool $torExit = false,
        public readonly int $localRiskBucket = 0,
    ) {
        if ($localRiskBucket < 0 || $localRiskBucket > 255) {
            throw new \InvalidArgumentException(
                sprintf('localRiskBucket must be within 0..255 (got %d)', $localRiskBucket)
            );
        }
    }

    public function blocked(): bool
    {
        return $this->localRiskBucket === 255;
    }

    /**
     * Fixed-point network risk contribution (P1 rescale — only deliberately
     * blocked/impossible networks hard-deny; the policy's >= 900 Deny rule
     * is reached by blocked (1000) and reserved/impossible (950) alone):
     * blocked -> 1000, reserved -> 950, known_proxy -> 750, tor -> 650,
     * known_hosting -> 600, ordinary -> 0. When several flags apply the
     * highest risk wins.
     */
    public function networkRisk(): int
    {
        if ($this->blocked()) {
            return 1000;
        }
        if ($this->reserved) {
            return 950;
        }
        if ($this->knownProxy) {
            return 750;
        }
        if ($this->torExit) {
            return 650;
        }
        if ($this->knownHosting) {
            return 600;
        }
        return 0;
    }
}
