<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * A Predis client whose central-policy reads can fail on demand, to
 * model a partitioned security-policy Redis for the region clock skew
 * tests. Every other command stays real; only the hgetall of the
 * central policy hash is intercepted. The SecurityEpochMonitor catches
 * the throwable and serves the last-observed max, the documented
 * fail-safe path, while the max-stale deadline drifts toward stale.
 */
final class PartitionedPredisClient extends \Predis\Client
{
    public bool $failReads = false;

    public function __construct(string $url)
    {
        parent::__construct($url);
    }

    public function __call($commandID, $arguments)
    {
        if ($this->failReads && strtolower((string) $commandID) === 'hgetall') {
            throw new \RuntimeException('partitioned policy read');
        }

        return parent::__call($commandID, $arguments);
    }
}
