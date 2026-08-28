<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * Long-lived-runtime-only pre-Redis shield: a single fixed-window limiter
 * of `processPerSecond` observations per second per process, enforced
 * before any state backend is touched.
 *
 * Runtime requirement: the window lives in this object's memory, so it
 * provides temporal protection only inside a persistent worker
 * (RoadRunner, Swoole, amphp) or a single CLI process. Under conventional
 * PHP-FPM the service graph is rebuilt per request, so this cap is
 * request-local: its queue never accumulates the previous request's
 * admissions and it provides no temporal pre-Redis cap at all. The
 * distributed Redis risk controls (source_fast/source_slow velocity,
 * keyed rate limits) are unaffected and remain authoritative across
 * workers in every deployment shape.
 *
 * This is a per-process admission cap, not a per-source limit: it bounds
 * how much work a single process may push at the state backend so a burst
 * cannot saturate this process's Redis connection. Per-source (and
 * per-identity) limits are the distributed keyed layer's job (the
 * source_fast/source_slow velocity in risk-v1 plus the keyed rate limiter
 * the caller feeds back through SourceRateLimitHit).
 *
 * Timestamps live in an SplQueue as hrtime(true) nanoseconds (monotonic
 * clock, so a wall-clock jump can never hold the window open or reopen it
 * early). Expired entries are dequeued from the front in O(1) amortized
 * time, so a saturated window never degrades into an O(n) scan; the
 * `$denied` bookkeeping was removed because it made the limiter
 * CPU-amplifying under flood.
 *
 * The contract is deliberately per-process (timestamps in this process's
 * memory); no cross-process synchronization is performed. When the window
 * is saturated the engine denies immediately (HardRateLimit) instead of
 * spending time/state on the request.
 *
 * Warm-up ramp: after every restart/autoscale the process must not
 * start with a full burst. The effective cap ramps linearly from a floor
 * of `max(1, processPerSecond / 10)` to the full cap over the first
 * `warmupRampSecs` seconds of the process's life. The formula:
 *
 *   effective_cap = processPerSecond * min(1, elapsed / warmupRampSecs),
 *                   floored at max(1, processPerSecond / 10).
 *
 * elapsed is measured on the same monotonic hrtime clock as the window,
 * so the ramp is immune to wall-clock jumps (a jump can neither extend
 * the ramp nor finish it early). `warmupRampSecs = 0` disables the ramp
 * (the full cap applies from the first call). The ramp only lowers the
 * admission rate during startup; the distributed keyed limits
 * (source_fast/source_slow velocity in risk-v1 plus the caller's
 * per-source rate limiter) remain authoritative — the ramp never raises
 * any limit beyond the configured processPerSecond.
 */
final class ProcessEmergencyCap
{
    public const DEFAULT_PROCESS_PER_SECOND = 10000;

    /** Default warm-up ramp length in seconds. */
    public const DEFAULT_WARMUP_RAMP_SECS = 10;

    /** Window length in nanoseconds (1 s on the monotonic hrtime clock). */
    private const WINDOW_NS = 1_000_000_000;

    /** @var \SplQueue<int> hrtime(true) nanosecond stamps of recent allowances */
    private \SplQueue $stamps;

    /** hrtime(true) nanoseconds at construction: the ramp's t=0. */
    private readonly int $startedAtNs;

    public function __construct(
        private readonly int $processPerSecond = self::DEFAULT_PROCESS_PER_SECOND,
        private readonly float $warmupRampSecs = self::DEFAULT_WARMUP_RAMP_SECS,
    ) {
        if ($processPerSecond < 1) {
            throw new \InvalidArgumentException('Limiter window must be >= 1');
        }
        if ($warmupRampSecs < 0.0) {
            throw new \InvalidArgumentException('warmupRampSecs must be >= 0 (0 disables the ramp)');
        }
        $this->startedAtNs = hrtime(true);
        $this->stamps = new \SplQueue();
    }

    /** The warm-up ramp length in seconds (0 = ramp disabled). */
    public function warmupRampSecs(): float
    {
        return $this->warmupRampSecs;
    }

    /**
     * True when the process may proceed within the current window. Also
     * marks the current moment as consumed.
     */
    public function allow(): bool
    {
        $now = hrtime(true);
        $this->prune($now);
        if ($this->stamps->count() >= $this->effectiveCap($now)) {
            return false;
        }
        $this->stamps->enqueue($now);
        return true;
    }

    /** True when the window is currently saturated. */
    public function isOpen(): bool
    {
        $now = hrtime(true);
        $this->prune($now);
        return $this->stamps->count() >= $this->effectiveCap($now);
    }

    /**
     * The cap in force at $nowNs: the full processPerSecond after the
     * warm-up ramp, and during the ramp a linear interpolation from the
     * floor of max(1, processPerSecond / 10). Monotonic in elapsed, so
     * the queue can never hold more than the full cap; the O(1) amortized
     * prune is preserved.
     */
    private function effectiveCap(int $nowNs): int
    {
        if ($this->warmupRampSecs <= 0.0) {
            return $this->processPerSecond;
        }
        $elapsedSecs = ($nowNs - $this->startedAtNs) / 1_000_000_000;
        if ($elapsedSecs >= $this->warmupRampSecs) {
            return $this->processPerSecond;
        }
        $floor = max(1, intdiv($this->processPerSecond, 10));
        $ramped = (int) floor($this->processPerSecond * $elapsedSecs / $this->warmupRampSecs);
        return max($floor, $ramped);
    }

    /**
     * Dequeues every entry at or before now - 1 s from the queue front.
     * hrtime is monotonic: elapsed can never be negative, so a wall-clock
     * jump backwards cannot extend the window.
     */
    private function prune(int $now): void
    {
        $cutoff = $now - self::WINDOW_NS;
        while (!$this->stamps->isEmpty() && $this->stamps->bottom() <= $cutoff) {
            $this->stamps->dequeue();
        }
    }
}

// BC alias: the per-process emergency cap was renamed from
// LocalEmergencyLimiter; the former class name must keep resolving for the
// Symfony bundle's existing wiring until it is updated to the new name.
if (!class_exists(LocalEmergencyLimiter::class, false)) {
    class_alias(ProcessEmergencyCap::class, LocalEmergencyLimiter::class);
}
