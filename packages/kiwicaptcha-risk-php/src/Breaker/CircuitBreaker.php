<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Breaker;

/**
 * In-process circuit breaker guarding the risk state backend.
 *
 * After `failureThreshold` consecutive failures the breaker opens for
 * `openMs`; while open, the engine skips the state backend entirely and
 * returns degraded decisions. Any success closes it again.
 *
 * Counters are per-instance (in-process, non-persistent): independent
 * breakers never bleed state into each other.
 */
final class CircuitBreaker
{
    private int $failures = 0;
    private ?float $openedAt = null;

    public function __construct(
        private readonly int $failureThreshold = 2,
        private readonly int $openMs = 1000,
    ) {
        if ($failureThreshold < 1) {
            throw new \InvalidArgumentException('failureThreshold must be >= 1');
        }
        if ($openMs < 1) {
            throw new \InvalidArgumentException('openMs must be >= 1');
        }
    }

    public function isOpen(): bool
    {
        if ($this->openedAt === null) {
            return false;
        }
        if ((microtime(true) - $this->openedAt) * 1000 >= $this->openMs) {
            $this->openedAt = null;
            $this->failures = 0;
            return false;
        }
        return true;
    }

    public function recordFailure(): void
    {
        if ($this->openedAt !== null) {
            return;
        }
        $this->failures++;
        if ($this->failures >= $this->failureThreshold) {
            $this->openedAt = microtime(true);
        }
    }

    public function recordSuccess(): void
    {
        $this->failures = 0;
        $this->openedAt = null;
    }
}
