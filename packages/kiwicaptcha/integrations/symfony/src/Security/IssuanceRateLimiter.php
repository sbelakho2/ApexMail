<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Rate limiter for challenge issuance: per-client-IP AND deployment-global.
 *
 * Deployment hardening: challenge issuance must be rate-limited, otherwise an
 * attacker can mint unlimited challenges and drive unbounded aggregate
 * verification work (each challenge costs the server an HMAC re-check and,
 * for Argon2id, a memory-hard hash on every submit attempt).
 *
 * Three backends, in priority order:
 *
 *  1. Redis (atomic, cross-worker): when a Redis client is available, a
 *     single Lua script implements the audit's atomic sliding window for BOTH
 *     the per-client ZSET and the deployment-global ZSET. `TIME` (the Redis
 *     server clock) drives the window, so all PHP-FPM workers share one
 *     consistent window and the enforcement is a GATE, not a bound.
 *  2. PSR-6 pool (shared, best-effort): when a shared pool is configured but
 *     no Redis client exists, the per-client window is kept in the pool. A
 *     PSR-6 pool cannot express an atomic read-modify-write, so concurrent
 *     requests may briefly exceed the limit — a bound, not a gate.
 *  3. In-memory (per-process): single-worker fallback.
 *
 * PRIVACY: raw client IPs are never stored. Every key (Redis, PSR-6 and
 * in-memory) is a peppered HMAC of the IP — `hash_hmac('sha256', $ip,
 * $pepper)` — where the pepper defaults to the bundle secret key
 * (`rate_limit_pepper` overrides it). The same HMAC is used by all backends
 * so they agree on the same identity.
 *
 * True sliding window (all backends): the state is a set of hit
 * timestamps/members pruned to `[now - window, now]` on every check — no
 * fixed [window_start, hits] bucket, so a burst straddling a window boundary
 * can never double the allowed rate.
 *
 * Results: {@see self::check()} returns 1 (allowed), 0 (per-client limit
 * reached) or -1 (GLOBAL limit reached). {@see self::allow()} is the boolean
 * view for callers that do not distinguish.
 */
final class IssuanceRateLimiter
{
    private const CACHE_KEY_PREFIX = 'kiwi_rate_';

    /**
     * Atomic per-client + global sliding window (exact audit semantics):
     *   KEYS[1]  = per-client ZSET
     *   KEYS[2]  = global ZSET
     *   ARGV[1]  = per-client max
     *   ARGV[2]  = global max
     *   ARGV[3]  = window in ms
     *   ARGV[4]  = unique request id (shared member in both ZSETs)
     * Returns 1 when allowed, 0 when the per-client cap is full, -1 when the
     * GLOBAL cap is full (both checked after pruning expired hits).
     */
    private const LIMIT_SCRIPT = <<<'LUA'
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
local cutoff = now - tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', cutoff)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then return -1 end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('ZADD', KEYS[2], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]) + 1000)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[3]) + 1000)
return 1
LUA;

    /** @var array<string, list<float>> sliding-window hit timestamps, per process */
    private array $hits = [];

    /**
     * @param int                        $maxChallenges 0 disables the per-client limit
     * @param int                        $windowSecs    sliding-window size in seconds
     * @param CacheItemPoolInterface|null $pool          shared multi-process state
     * @param \Closure|null              $now           epoch-seconds clock override for tests
     * @param string                     $pepper        HMAC pepper for client identities
     * @param \Redis|\Predis\Client|null $redis         when set, the ATOMIC Redis backend
     *                                                  is used (per-client + global)
     * @param int                        $globalMax     0 disables the global limit
     *                                                  (enforced in the Redis backend)
     * @param string                     $namespace     deployment discriminator for the
     *                                                  Redis keys (sanitized to
     *                                                  [A-Za-z0-9_.-])
     */
    public function __construct(
        private readonly int $maxChallenges,
        private readonly int $windowSecs,
        private readonly ?CacheItemPoolInterface $pool = null,
        private readonly ?\Closure $now = null,
        private readonly string $pepper = 'kiwicaptcha-rate-limit',
        private readonly \Redis|\Predis\Client|null $redis = null,
        private readonly int $globalMax = 0,
        string $namespace = '',
    ) {
        $this->namespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', $namespace) ?: '';
    }

    /** @var string sanitized deployment namespace for Redis keys */
    private readonly string $namespace;

    /**
     * @return bool true when the request may proceed
     */
    public function allow(string $clientIp): bool
    {
        return $this->check($clientIp) === 1;
    }

    /**
     * @return int 1 = allowed, 0 = per-client limit reached, -1 = GLOBAL
     *             limit reached
     */
    public function check(string $clientIp): int
    {
        if ($this->maxChallenges <= 0 && ($this->redis === null || $this->globalMax <= 0)) {
            return 1;
        }
        // An unknown client IP must never bypass the limit: bucket it with
        // the other unidentifiable clients instead (conservative, shared
        // budget). The IP itself is never used as a key — only the HMAC.
        $identity = $clientIp === '' ? 'unknown' : $clientIp;
        $key = hash_hmac('sha256', $identity, $this->pepper);

        if ($this->redis !== null) {
            return $this->checkRedis($key);
        }

        return $this->maxChallenges > 0
            ? (int) ($this->pool !== null ? $this->allowShared($key) : $this->allowLocal($key))
            : 1;
    }

    private function checkRedis(string $identity): int
    {
        $clientKey = 'kiwi:rl:client:'.$this->namespace.':'.$identity;
        $globalKey = 'kiwi:rl:global:'.$this->namespace;
        $windowMs = $this->windowSecs * 1000;
        $requestId = bin2hex(random_bytes(16));
        $clientMax = $this->maxChallenges > 0 ? $this->maxChallenges : \PHP_INT_MAX;
        $globalMax = $this->globalMax > 0 ? $this->globalMax : \PHP_INT_MAX;

        $result = $this->eval(self::LIMIT_SCRIPT, [$clientKey, $globalKey], [
            (string) $clientMax,
            (string) $globalMax,
            (string) $windowMs,
            $requestId,
        ]);

        return (int) $result;
    }

    private function allowLocal(string $key): bool
    {
        $now = $this->now();
        $hits = $this->hits[$key] ?? [];

        $hits = $this->prune($hits, $now);

        if (\count($hits) >= $this->maxChallenges) {
            $this->hits[$key] = $hits;

            return false;
        }
        $hits[] = $now;
        $this->hits[$key] = $hits;

        return true;
    }

    private function allowShared(string $key): bool
    {
        $cacheKey = self::CACHE_KEY_PREFIX.$key;

        $item = $this->pool->getItem($cacheKey);
        $state = $item->isHit() ? $item->get() : null;
        $hits = \is_array($state) ? $this->timestamps($state) : [];

        $now = $this->now();
        $hits = $this->prune($hits, $now);

        if (\count($hits) >= $this->maxChallenges) {
            $item->set(['t' => $hits]);
            $item->expiresAfter($this->windowSecs + 1);
            $this->pool->save($item);

            return false;
        }
        $hits[] = $now;

        $item->set(['t' => $hits]);
        $item->expiresAfter($this->windowSecs + 1);
        $this->pool->save($item);

        return true;
    }

    /**
     * @param array<string, mixed> $state
     *
     * @return list<float>
     */
    private function timestamps(array $state): array
    {
        $raw = $state['t'] ?? [];
        if (!\is_array($raw)) {
            return [];
        }
        $ts = [];
        foreach ($raw as $v) {
            $ts[] = (float) $v;
        }

        return $ts;
    }

    /**
     * @param list<float> $hits
     *
     * @return list<float>
     */
    private function prune(array $hits, float $now): array
    {
        $cutoff = $now - $this->windowSecs;

        return array_values(array_filter($hits, static fn (float $ts): bool => $ts >= $cutoff));
    }

    private function now(): float
    {
        return $this->now !== null ? (float) ($this->now)() : microtime(true);
    }

    /**
     * Run a Lua script against whichever client implementation is in use.
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
}
