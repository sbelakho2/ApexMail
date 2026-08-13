<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * PER-SCOPE issuance cap (audit #89): a Redis fixed-window counter bounding
 * how many challenges a scope may issue per minute.
 *
 * Key: `{kiwi:<ns>}:issuance:<scope>:<minute>` — one independent window per
 * scope per minute (the minute is derived from the Redis server clock when
 * Redis is the backend, so all workers share one window even when an
 * application host's wall clock drifts). The key shares the risk store's
 * hash-tag family (Cluster safe).
 *
 * ONE atomic Lua script (INCR + EXPIRE in a single round trip): the first
 * increment of a fresh window stamps its 60 s TTL, and the cap is checked on
 * the returned count — a concurrent reader can never observe an INCR-ed
 * value without its expiry, and the counter can never persist past its
 * minute.
 *
 * The cap is a GATE, not a bound: a request that consumes the last slot is
 * admitted, the next one in the same window is refused (the controller
 * returns 429 SCOPE_LIMITED before any challenge is minted).
 *
 * A Redis failure PROPAGATES (fail closed): the caller refuses issuance
 * rather than minting an unbilled challenge — the deployment-wide billed-work
 * cap must not silently degrade to unlimited.
 */
final class ScopeIssuanceCap
{
    /**
     * Atomic increment + expiry + cap check:
     *   KEYS[1] = {kiwi:<ns>}:issuance:<scope>:<minute>
     *   ARGV[1] = cap
     * Returns 1 when the window has room, 0 when the cap is exhausted.
     */
    private const CHECK_SCRIPT = <<<'LUA'
-- Scope issuance cap: fixed-window INCR + EXPIRE 60, refuse beyond the cap
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end
if n > tonumber(ARGV[1]) then return 0 end
return 1
LUA;

    /**
     * @param \Redis|\Predis\Client|null $redis     the security Redis (null =
     *                                              cap disabled — no-op)
     * @param string                     $keyPrefix full key prefix including
     *                                              the hash tag, e.g.
     *                                              "{kiwi:prod}:issuance:"
     * @param int                        $cap       per-scope per-minute cap
     *                                              (0 = unlimited, no-op)
     * @param \Closure|null              $now       epoch-seconds clock override
     *                                              for tests (falls back to the
     *                                              Redis server clock when
     *                                              Redis is the backend)
     */
    public function __construct(
        private readonly \Redis|\Predis\Client|null $redis = null,
        private readonly string $keyPrefix = '{kiwi:kiwi}:issuance:',
        private readonly int $cap = 0,
        private readonly ?\Closure $now = null,
    ) {
    }

    /**
     * Whether the scope's window has room for one more issuance. CONSUMING:
     * an allowed check increments the window counter (the callers counts the
     * issuance it then performs). Never throws for a disabled cap (null
     * Redis or cap 0) — always allowed.
     *
     * @throws \Throwable when Redis fails (fail closed — the caller refuses
     *                    issuance rather than minting an unbilled challenge)
     */
    public function allow(string $scope): bool
    {
        if ($this->redis === null || $this->cap <= 0) {
            return true;
        }

        $result = $this->eval(self::CHECK_SCRIPT, [$this->windowKey($scope)], [(string) $this->cap]);

        return (int) $result === 1;
    }

    /**
     * The fixed-window key for a scope: `{kiwi:<ns>}:issuance:<scope>:<minute>`.
     * The minute comes from the Redis server clock (one TIME read shared with
     * the script's EXPIRE) or the injected clock when Redis is unavailable.
     */
    public function windowKey(string $scope): string
    {
        return sprintf('%s%s:%d', $this->keyPrefix, $scope, $this->minute());
    }

    /**
     * Run the Lua script against whichever client implementation is in use.
     *
     * @param list<string> $keys
     * @param list<string> $args
     */
    private function eval(string $script, array $keys, array $args): mixed
    {
        if ($this->redis instanceof \Redis) {
            // phpredis signature: eval($script, $args, $numKeys)
            return $this->redis->eval($script, [...$keys, ...$args], \count($keys));
        }

        // Predis signature: eval($script, $numkeys, ...$keysAndArgs)
        return $this->redis->eval($script, \count($keys), ...$keys, ...$args);
    }

    private function minute(): int
    {
        if ($this->now !== null) {
            return intdiv((int) ($this->now)(), 60);
        }
        try {
            $time = $this->redis->time();
            if (\is_array($time) && isset($time[0])) {
                return intdiv((int) $time[0], 60);
            }
        } catch (\Throwable) {
            // Fall through to the local clock; the script still expires the
            // key, so a drifted window is bounded by the EXPIRE.
        }

        return intdiv(time(), 60);
    }
}
