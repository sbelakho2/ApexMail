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

    /** Monotonic-ms stamp (hrtime) when the breaker opened; null = closed. */
    private ?float $openedAtMs = null;

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
        if ($this->openedAtMs === null) {
            return false;
        }
        if (self::monotonicMs() - $this->openedAtMs >= $this->openMs) {
            $this->openedAtMs = null;
            $this->failures = 0;
            return false;
        }

        return true;
    }

    public function recordFailure(): void
    {
        if ($this->openedAtMs !== null) {
            return;
        }
        $this->failures++;
        if ($this->failures >= $this->failureThreshold) {
            $this->openedAtMs = self::monotonicMs();
        }
    }

    public function recordSuccess(): void
    {
        $this->failures = 0;
        $this->openedAtMs = null;
    }

    /**
     * Monotonic milliseconds since an arbitrary process-relative origin.
     * NOT the wall clock: an NTP step backwards used to make the elapsed
     * delta negative (or zero), keeping the breaker open — and every
     * decision degraded — until the clock caught back up.
     */
    private static function monotonicMs(): float
    {
        return hrtime(true) / 1_000_000;
    }
}
