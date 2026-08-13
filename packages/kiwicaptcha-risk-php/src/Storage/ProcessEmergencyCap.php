<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * Per-process emergency cap: a single fixed-window limiter of
 * `processPerSecond` observations per second per process, enforced BEFORE
 * any state backend is touched.
 *
 * This is a per-PROCESS admission cap, NOT a per-source limit: it bounds
 * how much work a single process may push at the state backend so a burst
 * cannot saturate this process's Redis connection. Per-source (and
 * per-identity) limits are the distributed keyed layer's job (the
 * source_fast/source_slow velocity in risk-v1 plus the keyed rate limiter
 * the caller feeds back through SourceRateLimitHit).
 *
 * Timestamps live in an SplQueue: expired entries are dequeued from the
 * FRONT in O(1) amortized time, so a saturated window never degrades into
 * an O(n) scan (no `$denied` bookkeeping — it contributed nothing and made
 * the limiter CPU-amplifying under flood).
 *
 * The contract is deliberately per-process (timestamps in this process's
 * memory); no cross-process synchronization is performed. When the window
 * is saturated the engine denies immediately (HardRateLimit) instead of
 * spending time/state on the request.
 */
final class ProcessEmergencyCap
{
    public const DEFAULT_PROCESS_PER_SECOND = 10000;

    /** @var \SplQueue<float> microtime(true) stamps of recent allowances */
    private \SplQueue $stamps;

    public function __construct(
        private readonly int $processPerSecond = self::DEFAULT_PROCESS_PER_SECOND,
    ) {
        if ($processPerSecond < 1) {
            throw new \InvalidArgumentException('Limiter window must be >= 1');
        }
        $this->stamps = new \SplQueue();
    }

    /**
     * True when the process may proceed within the current window. Also
     * marks the current moment as consumed.
     */
    public function allow(): bool
    {
        $now = microtime(true);
        $this->prune($now);
        if ($this->stamps->count() >= $this->processPerSecond) {
            return false;
        }
        $this->stamps->enqueue($now);
        return true;
    }

    /** True when the window is currently saturated. */
    public function isOpen(): bool
    {
        $this->prune(microtime(true));
        return $this->stamps->count() >= $this->processPerSecond;
    }

    /** Dequeues every entry at or before now - 1.0 from the queue front. */
    private function prune(float $now): void
    {
        $cutoff = $now - 1.0;
        while (!$this->stamps->isEmpty() && $this->stamps->bottom() <= $cutoff) {
            $this->stamps->dequeue();
        }
    }
}

// BC alias: the per-process emergency cap was renamed from
// LocalEmergencyLimiter; the old class name must keep resolving for the
// Symfony bundle's existing wiring until it is updated to the new name.
if (!class_exists(LocalEmergencyLimiter::class, false)) {
    class_alias(ProcessEmergencyCap::class, LocalEmergencyLimiter::class);
}
