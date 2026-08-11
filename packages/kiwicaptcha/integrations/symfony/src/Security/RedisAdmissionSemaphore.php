<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * Redis-backed admission semaphore capping concurrent Argon2id
 * verifications ACROSS all PHP-FPM workers sharing the Redis instance.
 *
 * The in-process {@see Argon2Semaphore} bounds concurrency per worker only
 * (PHP-FPM workers share no memory); this semaphore replaces it when the
 * bundle has a Redis client (the configured storage is RedisStorage, or a
 * `redis_service` config option is set). Admission is atomic: a single Lua
 * INCR/DECR decides whether a permit is available, so N workers can never
 * exceed the cap together.
 *
 * Key: `kiwicaptcha:argon2:active:<suffix>` (one counter per deployment —
 * the suffix is derived from the RedisStorage prefix when the client comes
 * from the storage service, or defaults to a stable bundle constant).
 *
 * APPROXIMATION (documented): permits are guarded by a watchdog TTL
 * (default 60 s) instead of exact liveness. If a worker crashes (or the
 * request dies) while holding a permit, the counter is never DECRed by that
 * worker — the permit simply expires after the watchdog, slightly shrinking
 * the effective cap for up to one watchdog period. The acquire script
 * refreshes the watchdog on every INCR, so live permits never expire. This
 * is an admission bound, not a mutex: under a crash storm the cap may be
 * briefly exceeded by the number of permits that expired between the crash
 * and the next acquire, which is acceptable for memory-cost bounding.
 */
final class RedisAdmissionSemaphore
{
    private const DEFAULT_KEY_SUFFIX = 'default';

    /** Watchdog TTL in seconds: leaked permits (crashed workers) auto-expire. */
    private const WATCHDOG_TTL_SECS = 60;

    /**
     * Atomic admission test:
     *   KEYS[1]  = semaphore counter key
     *   ARGV[1]  = cap (max concurrent)
     *   ARGV[2]  = watchdog TTL in seconds
     * Returns 1 when the permit was granted, 0 when the cap is saturated
     * (the INCR is rolled back, so no permit is leaked).
     */
    private const ACQUIRE_SCRIPT = <<<'LUA'
local n = redis.call('INCR', KEYS[1])
if n == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
if n > tonumber(ARGV[1]) then
    redis.call('DECR', KEYS[1])
    return 0
end
return 1
LUA;

    /**
     * Permit release. The counter is DECRed with a floor at 0: a release
     * with no outstanding permit (e.g. after the watchdog expired the
     * counter) removes the key so the next acquire starts clean at 1.
     *
     * KEYS[1] = semaphore counter key
     */
    private const RELEASE_SCRIPT = <<<'LUA'
local n = redis.call('DECR', KEYS[1])
if n < 0 then
    redis.call('DEL', KEYS[1])
end
LUA;

    private readonly string $key;

    /**
     * @param \Redis|\Predis\Client $client Redis client (phpredis or Predis —
     *                                      the same clients RedisStorage
     *                                      accepts; the bundle itself has no
     *                                      hard dependency on either)
     * @param int                   $maxConcurrent cap; <= 0 disables the cap
     * @param string                $keySuffix      stable per-deployment
     *                                              discriminator (e.g. the
     *                                              storage prefix)
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly int $maxConcurrent,
        string $keySuffix = self::DEFAULT_KEY_SUFFIX,
    ) {
        $suffix = preg_replace('/[^A-Za-z0-9_.-]/', '_', $keySuffix) ?: self::DEFAULT_KEY_SUFFIX;
        $this->key = 'kiwicaptcha:argon2:active:'.$suffix;
    }

    public function acquire(): bool
    {
        if ($this->maxConcurrent <= 0) {
            return true;
        }
        $result = $this->eval(self::ACQUIRE_SCRIPT, [$this->key], [(string) $this->maxConcurrent, (string) self::WATCHDOG_TTL_SECS]);

        return $result === 1;
    }

    public function release(): void
    {
        $this->eval(self::RELEASE_SCRIPT, [$this->key], []);
    }

    /**
     * Run a Lua script against whichever client implementation is in use.
     *
     * @param list<string> $keys
     * @param list<string> $args
     */
    private function eval(string $script, array $keys, array $args): mixed
    {
        if ($this->client instanceof \Redis) {
            // phpredis signature: eval($script, $args, $numKeys)
            return $this->client->eval($script, [...$keys, ...$args], \count($keys));
        }

        // Predis signature: eval($script, $numkeys, ...$keysAndArgs)
        return $this->client->eval($script, \count($keys), ...$keys, ...$args);
    }
}
