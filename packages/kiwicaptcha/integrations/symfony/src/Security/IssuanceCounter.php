<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * Atomic Redis issuance-rate signal for the live resource-pressure provider.
 *
 * The challenge controller calls {@see record()} for every minted challenge;
 * the provider reads the current second's counter to compute issuance
 * headroom (max(0, global_per_second - rate)). The key
 * {kiwi:<namespace>}:issuance:<unix-second> shares the risk store's hash-tag
 * family (Cluster safe) and is expired after 1 s so the signal always
 * reflects the LIVE per-second rate without a cleanup job.
 *
 * The counter is pure telemetry for the risk policy's capacity-denial path:
 * any failure (Redis down, timeout, wrong protocol) is swallowed — issuance
 * must never break over the telemetry path, and an unavailable source must
 * never fabricate artificial scarcity.
 */
final class IssuanceCounter
{
    /**
     * @param \Redis|\Predis\Client|null $redis     client used for the atomic
     *                                              INCR/EXPIRE (null = counter
     *                                              disabled, no-op)
     * @param string                     $keyPrefix full key prefix including
     *                                              the hash tag, e.g.
     *                                              "{kiwi:prod}:issuance:"
     */
    public function __construct(
        private readonly \Redis|\Predis\Client|null $redis = null,
        private readonly string $keyPrefix = '{kiwi:kiwi}:issuance:',
    ) {
    }

    /** The Redis key for one unix-second bucket (shared with the provider). */
    public static function rateKey(string $keyPrefix, ?int $second = null): string
    {
        return sprintf('%s%d', $keyPrefix, $second ?? time());
    }

    /**
     * Record one issued challenge in the current second's counter (INCR +
     * EXPIRE 1, atomic). Never throws.
     */
    public function record(?int $second = null): void
    {
        if ($this->redis === null) {
            return;
        }
        try {
            $key = self::rateKey($this->keyPrefix, $second);
            $this->redis->incr($key);
            $this->redis->expire($key, 1);
        } catch (\Throwable) {
            // Telemetry only — never break issuance over the counter.
        }
    }
}
