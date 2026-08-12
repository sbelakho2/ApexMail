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
     * Fixed-point network risk contribution: 1000 for reserved/hosting/
     * proxy/blocked sources, 600 for Tor exits, 0 otherwise.
     */
    public function networkRisk(): int
    {
        if ($this->reserved || $this->knownHosting || $this->knownProxy || $this->blocked()) {
            return 1000;
        }
        if ($this->torExit) {
            return 600;
        }
        return 0;
    }
}
