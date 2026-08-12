<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * In-process emergency guard: a fixed-window limiter of 100 observations
 * per second per process, enforced BEFORE any state backend is touched.
 *
 * The contract is deliberately per-process (an array of timestamps in this
 * process's memory); no cross-process synchronization is performed. When
 * the window is saturated the engine denies immediately (HardRateLimit)
 * instead of spending time/state on the request.
 */
final class LocalEmergencyLimiter
{
    public const MAX_PER_SECOND = 100;

    /** @var list<float> microtime(true) stamps of recent allowances */
    private array $stamps = [];

    /** @var list<float> microtime(true) stamps of denials */
    private array $denied = [];

    /**
     * True when the process may proceed within the current window.
     * Also marks the current moment as consumed.
     */
    public function allow(): bool
    {
        $now = microtime(true);
        $this->prune($now);
        if (count($this->stamps) >= self::MAX_PER_SECOND) {
            $this->denied[] = $now;
            return false;
        }
        $this->stamps[] = $now;
        return true;
    }

    /** True when the window is currently saturated. */
    public function isOpen(): bool
    {
        $this->prune(microtime(true));
        return count($this->stamps) >= self::MAX_PER_SECOND;
    }

    private function prune(float $now): void
    {
        $cutoff = $now - 1.0;
        $this->stamps = array_values(array_filter($this->stamps, static fn (float $t): bool => $t > $cutoff));
        $this->denied = array_values(array_filter($this->denied, static fn (float $t): bool => $t > $cutoff));
    }
}
