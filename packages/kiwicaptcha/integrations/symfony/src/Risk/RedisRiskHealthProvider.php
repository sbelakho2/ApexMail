<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\ResourcePressure;

/**
 * Live resource-pressure provider backed by the bundle's own observables:
 *
 *  - argonCapacity: remaining slots of the Redis-backed Argon2id admission
 *    semaphore (0 = saturated, 1000 = idle). Null semaphore (no Redis
 *    semaphore wired, or argon_capacity.enabled = false) -> nominal 1000.
 *  - issuanceCapacity: REAL per-second issuance headroom from the atomic
 *    Redis issuance-rate signal ({kiwi:<ns>}:issuance:<second>, incremented
 *    by the challenge controller on every minted challenge):
 *    clamp(max(0, hard_limits.global_per_second - current_rate), 0..1000)
 *    (the ResourcePressure contract is fixed-point 0..1000; 1000 = full
 *    headroom, and the policy denies when headroom drops below 100). A
 *    counter unbounded by a global cap (global_per_second <= 0) or an
 *    unavailable counter (no client / Redis failure) -> nominal 1000.
 *  - riskBackendHealth: the risk state store's LAST operation result via
 *    the engine's circuit breaker (injected alongside the engine): breaker
 *    open (recent consecutive store failures) -> 0, closed -> 1000. NO
 *    per-request PING — the breaker state is derived from the operations
 *    the hot path already performs. Null breaker -> nominal 1000.
 *
 * The whole snapshot() is cached for 100 ms (in-process timestamp cache):
 * the hot path performs at most one Redis read per 100 ms on top of the
 * risk-state round trip, instead of a PING + two semaphore queries per
 * request.
 *
 * Any source that cannot be observed reports the nominal 1000 — pressure is
 * an availability signal and an unavailable source must never fabricate
 * artificial scarcity. The policy's capacity-denial paths
 * (issuanceCapacity < 100 denies, argonCapacity < 300 degrades Argon to
 * Sha20) therefore only engage when the bundle can actually measure the
 * resource.
 */
final class RedisRiskHealthProvider implements ResourcePressureProviderInterface
{
    /** In-process snapshot cache lifetime in ms (hot-path budget). */
    private const CACHE_MS = 100;

    private ?ResourcePressure $cached = null;
    private float $cachedAtMs = 0.0;

    /**
     * @param string $issuanceKeyPrefix full issuance-counter key prefix
     *                                  including the hash tag, e.g.
     *                                  "{kiwi:prod}:issuance:"
     */
    public function __construct(
        private readonly ?RedisAdmissionSemaphore $semaphore = null,
        private readonly \Redis|\Predis\Client|null $redis = null,
        private readonly string $issuanceKeyPrefix = '{kiwi:kiwi}:issuance:',
        private readonly int $globalPerSecond = 10000,
        private readonly ?CircuitBreaker $breaker = null,
    ) {
    }

    public function snapshot(): ResourcePressure
    {
        $nowMs = microtime(true) * 1000;
        if ($this->cached !== null && $nowMs - $this->cachedAtMs < self::CACHE_MS) {
            return $this->cached;
        }

        $pressure = new ResourcePressure(
            argonCapacity: $this->argonCapacity(),
            issuanceCapacity: $this->issuanceCapacity(),
            riskBackendHealth: $this->backendHealth(),
        );
        $this->cached = $pressure;
        $this->cachedAtMs = $nowMs;

        return $pressure;
    }

    private function argonCapacity(): int
    {
        if ($this->semaphore === null) {
            return 1000;
        }
        $capacity = $this->semaphore->capacity();
        if ($capacity <= 0) {
            return 1000;
        }
        $usage = max(0, min($capacity, $this->semaphore->usage()));

        return max(0, min(1000, (int) round((1 - $usage / $capacity) * 1000)));
    }

    private function issuanceCapacity(): int
    {
        if ($this->redis === null || $this->globalPerSecond <= 0) {
            return 1000;
        }
        try {
            $rate = max(0, (int) $this->redis->get(IssuanceCounter::rateKey($this->issuanceKeyPrefix)));
        } catch (\Throwable) {
            // Unavailable counter: never fabricate artificial scarcity.
            return 1000;
        }

        return max(0, min(1000, $this->globalPerSecond - $rate));
    }

    private function backendHealth(): int
    {
        if ($this->breaker === null) {
            return 1000;
        }

        // The breaker state IS the last-operation signal: every store
        // success closes it, consecutive failures open it. No PING.
        return $this->breaker->isOpen() ? 0 : 1000;
    }
}
