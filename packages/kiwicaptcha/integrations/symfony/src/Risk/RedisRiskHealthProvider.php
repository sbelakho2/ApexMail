<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use KiwiCaptcha\Risk\ResourcePressure;

/**
 * Live resource-pressure provider backed by the bundle's own observables:
 *
 *  - argonCapacity: remaining slots of the Redis-backed Argon2id admission
 *    semaphore (0 = saturated, 1000 = idle). Null semaphore (no Redis
 *    semaphore wired, or argon_capacity.enabled = false) -> nominal 1000.
 *    An unknown usage, the semaphore is wired but its live-lease read
 *    failed (usage() -> null), is treated conservatively as 0 (saturated):
 *    the policy's capacity paths then escalate Argon to Sha20/StepUp
 *    instead of admitting more memory-hard work on a gate that cannot be
 *    measured (never fabricate headroom for a resource that is not
 *    observable).
 *  - issuanceCapacity: real per-second issuance headroom from the atomic
 *    Redis issuance-rate signal ({kiwi:<ns>}:issuance:<second>, incremented
 *    by the challenge controller on every minted challenge), as the
 *    remaining fraction of the deployment-wide
 *    resource_capacity.issuance_per_second:
 *    clamp(round(max(0, cap - rate) * 1000 / cap), 0..1000). 100% remaining
 *    -> 1000, 50% -> 500, 10% -> 100, 0% -> 0 (the ResourcePressure contract
 *    is fixed-point 0..1000; 1000 = full headroom, and the policy denies
 *    when headroom drops below 100). A counter unbounded by a cap
 *    (issuance_per_second <= 0) or an unavailable counter (no client / Redis
 *    failure) -> nominal 1000.
 *
 * The whole snapshot() is cached for 100 ms (in-process timestamp cache):
 * the hot path performs at most one Redis read per 100 ms on top of the
 * risk-state round trip, instead of a PING + two semaphore queries per
 * request.
 *
 * The two dimensions are asymmetric on an unobservable source by design:
 * an unobservable issuance counter reports nominal 1000 (pressure is an
 * availability signal and an unavailable source must never fabricate
 * artificial scarcity), while an unobservable Argon gate reports 0: the
 * gate bounds a real memory resource, so when it cannot be measured it is
 * assumed saturated rather than admitting unbounded Argon work. The
 * policy's capacity-denial paths (issuanceCapacity < 100 denies,
 * argonCapacity < 300 degrades Argon to Sha20) therefore only engage on
 * measured scarcity for issuance, and on both measured and unknown
 * scarcity for Argon.
 * Risk-backend health is not part of this snapshot anymore: the engine's
 * degraded mode consumes the shared circuit breaker directly (the breaker
 * is wired into the engine), so the provider never needs it.
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
        private readonly int $issuancePerSecond = 20000,
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
        $usage = $this->semaphore->usage();
        if ($usage === null) {
            // Unknown usage (backend unavailable): conservative 0 — the
            // policy escalates Argon to Sha20/StepUp instead of admitting
            // more memory-hard work on an unmeasurable gate.
            return 0;
        }
        $usage = max(0, min($capacity, $usage));

        return max(0, min(1000, (int) round((1 - $usage / $capacity) * 1000)));
    }

    private function issuanceCapacity(): int
    {
        if ($this->redis === null || $this->issuancePerSecond <= 0) {
            return 1000;
        }
        try {
            $rate = max(0, (int) $this->redis->get(IssuanceCounter::rateKey($this->issuanceKeyPrefix)));
        } catch (\Throwable) {
            // Unavailable counter: never fabricate artificial scarcity.
            return 1000;
        }

        $remaining = max(0, $this->issuancePerSecond - $rate);

        return max(0, min(1000, (int) round($remaining * 1000 / $this->issuancePerSecond)));
    }
}
