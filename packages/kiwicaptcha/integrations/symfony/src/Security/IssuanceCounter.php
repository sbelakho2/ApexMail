<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * Atomic Redis issuance-rate signal for the live resource-pressure provider.
 *
 * The challenge controller calls {@see record()} for every minted challenge;
 * the provider reads the current second's counter to compute issuance
 * headroom (max(0, process_per_second - rate)). The key
 * {kiwi:<namespace>}:issuance:<unix-second> shares the risk store's hash-tag
 * family (Cluster safe) and is expired after 1 s so the signal always
 * reflects the LIVE per-second rate without a cleanup job.
 *
 * The increment + expiry are ONE atomic Lua script (INCR + EXPIRE in a
 * single round trip): the counter can never persist past its second without
 * its TTL (a lost EXPIRE would leave a stale bucket that fabricates
 * artificial scarcity), and a concurrent reader can never observe the
 * INCR-ed value with a missing TTL.
 *
 * The counter is pure telemetry for the risk policy's capacity-denial path:
 * any failure (Redis down, timeout, wrong protocol) is swallowed — issuance
 * must never break over the telemetry path, and an unavailable source must
 * never fabricate artificial scarcity.
 */
final class IssuanceCounter
{
    /**
     * Atomic increment + expiry:
     *   KEYS[1] = {kiwi:<ns>}:issuance:<unix-second>
     * Returns the new counter value.
     */
    private const RECORD_SCRIPT = <<<'LUA'
local n = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], 1)
return n
LUA;

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
     * Record one issued challenge in the current second's counter (one
     * atomic Lua script: INCR + EXPIRE 1). Never throws.
     */
    public function record(?int $second = null): void
    {
        if ($this->redis === null) {
            return;
        }
        try {
            $key = self::rateKey($this->keyPrefix, $second);
            if ($this->redis instanceof \Redis) {
                // phpredis signature: eval($script, $args, $numKeys)
                $this->redis->eval(self::RECORD_SCRIPT, [$key], 1);
            } else {
                // Predis signature: eval($script, $numkeys, ...$keysAndArgs)
                $this->redis->eval(self::RECORD_SCRIPT, 1, $key);
            }
        } catch (\Throwable) {
            // Telemetry only — never break issuance over the counter.
        }
    }
}
