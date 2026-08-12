<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * In-process emergency guard: a fixed-window limiter of `maxPerSecond`
 * observations per second per process for the SOURCE window and
 * `globalPerSecond` per second for the GLOBAL window ({kiwi:<ns>}:limit:global
 * conceptually), enforced BEFORE any state backend is touched.
 *
 * The contract is deliberately per-process (arrays of timestamps in this
 * process's memory); no cross-process synchronization is performed. When a
 * window is saturated the engine denies immediately (HardRateLimit) instead
 * of spending time/state on the request.
 */
final class LocalEmergencyLimiter
{
    public const MAX_PER_SECOND = 100;
    public const DEFAULT_GLOBAL_PER_SECOND = 10000;

    /** @var list<float> microtime(true) stamps of recent source allowances */
    private array $stamps = [];

    /** @var list<float> microtime(true) stamps of recent global allowances */
    private array $globalStamps = [];

    /** @var list<float> microtime(true) stamps of denials */
    private array $denied = [];

    public function __construct(
        private readonly int $maxPerSecond = self::MAX_PER_SECOND,
        private readonly int $globalPerSecond = self::DEFAULT_GLOBAL_PER_SECOND,
    ) {
        if ($maxPerSecond < 1 || $globalPerSecond < 1) {
            throw new \InvalidArgumentException('Limiter windows must be >= 1');
        }
    }

    /**
     * True when the process may proceed within the current SOURCE window.
     * Also marks the current moment as consumed.
     */
    public function allow(): bool
    {
        $now = microtime(true);
        $this->stamps = $this->prune($this->stamps, $now);
        if (count($this->stamps) >= $this->maxPerSecond) {
            $this->denied[] = $now;
            return false;
        }
        $this->stamps[] = $now;
        return true;
    }

    /**
     * True when the process may proceed within the current GLOBAL window
     * (same leaky-window math as the source window). Also marks the current
     * moment as consumed.
     */
    public function allowGlobal(): bool
    {
        $now = microtime(true);
        $this->globalStamps = $this->prune($this->globalStamps, $now);
        if (count($this->globalStamps) >= $this->globalPerSecond) {
            $this->denied[] = $now;
            return false;
        }
        $this->globalStamps[] = $now;
        return true;
    }

    /** True when the SOURCE window is currently saturated. */
    public function isOpen(): bool
    {
        $this->stamps = $this->prune($this->stamps, microtime(true));
        return count($this->stamps) >= $this->maxPerSecond;
    }

    /** True when the GLOBAL window is currently saturated. */
    public function isOpenGlobal(): bool
    {
        $this->globalStamps = $this->prune($this->globalStamps, microtime(true));
        return count($this->globalStamps) >= $this->globalPerSecond;
    }

    /** @param list<float> $stamps @return list<float> */
    private function prune(array $stamps, float $now): array
    {
        $cutoff = $now - 1.0;
        $stamps = array_values(array_filter($stamps, static fn (float $t): bool => $t > $cutoff));
        $this->denied = array_values(array_filter($this->denied, static fn (float $t): bool => $t > $cutoff));
        return $stamps;
    }
}
