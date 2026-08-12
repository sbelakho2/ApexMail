<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use KiwiCaptcha\Risk\ResourcePressure;

/**
 * Live resource-pressure provider backed by the bundle's own observables:
 *
 *  - argonCapacity: remaining slots of the Redis-backed Argon2id admission
 *    semaphore (0 = saturated, 1000 = idle). Null semaphore (no Redis
 *    semaphore wired, or argon_capacity.enabled = false) -> nominal 1000.
 *  - issuanceCapacity: not observable in the bundle (the issuance rate
 *    limiters are enforcement, not telemetry) -> nominal 1000.
 *  - riskBackendHealth: a PING of the risk state-store Redis with a short
 *    timeout; any failure (unreachable, timeout, wrong protocol) -> 0.
 *    Null client -> nominal 1000.
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
    public function __construct(
        private readonly ?RedisAdmissionSemaphore $semaphore = null,
        private readonly \Redis|\Predis\Client|null $redis = null,
    ) {
    }

    public function snapshot(): ResourcePressure
    {
        return new ResourcePressure(
            argonCapacity: $this->argonCapacity(),
            issuanceCapacity: 1000,
            riskBackendHealth: $this->backendHealth(),
        );
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

    private function backendHealth(): int
    {
        if ($this->redis === null) {
            return 1000;
        }
        try {
            $this->redis->ping();

            return 1000;
        } catch (\Throwable) {
            return 0;
        }
    }
}
