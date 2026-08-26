<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Rate limiter for challenge issuance: per-client-IP and deployment-global.
 *
 * Deployment hardening: challenge issuance must be rate-limited, otherwise an
 * attacker can mint unlimited challenges and drive unbounded aggregate
 * verification work (each challenge costs the server an HMAC re-check and,
 * for Argon2id, a memory-hard hash on every submit attempt).
 *
 * Three backends, in priority order:
 *
 *  1. Redis (atomic, cross-worker): when a Redis client is available, a
 *     single Lua script implements the audit's atomic sliding window for both
 *     the per-client ZSET and the deployment-global ZSET. `TIME` (the Redis
 *     server clock) drives the window, so all PHP-FPM workers share one
 *     consistent window and the enforcement is an exact gate.
 *  2. PSR-6 pool (shared, best-effort): when a shared pool is configured but
 *     no Redis client exists, the per-client window is kept in the pool. A
 *     PSR-6 pool cannot express an atomic read-modify-write, so concurrent
 *     requests may briefly exceed the limit; this is a soft bound.
 *  3. In-memory (per-process): single-worker fallback.
 *
 * Privacy: raw client IPs are never stored. Every key (Redis, PSR-6 and
 * in-memory) is a peppered HMAC of the IP, `hash_hmac('sha256', $ip,
 * $pepper)`, where the pepper defaults to the bundle secret key
 * (`rate_limit_pepper` overrides it). The same HMAC is used by all backends
 * so they agree on the same identity.
 *
 * True sliding window (all backends): the state is a set of hit
 * timestamps/members pruned to `(now - window, now]` on every check, with
 * no fixed [window_start, hits] bucket. A burst straddling a window
 * boundary can never double the allowed rate.
 *
 * Exact-ms global window: the deployment-global ZSET holds one member
 * per admitted request, scored at the exact admission millisecond (Redis
 * TIME) — a member's timestamp is exact, so the sliding window is exact
 * at millisecond precision, not bucketed to the second. Every admission
 * prunes the members at `<= now - window` with `ZREMRANGEBYSCORE`,
 * checks the cap with `ZCARD` (the global count IS the global
 * cardinality) and records the admission with `ZADD now <member>`. The
 * per-admission work is O(pruned + ZCARD + `ZADD`), bounded by the member
 * count, which the global cap bounds: at most rate_limit_global members
 * ever coexist, whatever the window length or request volume.
 *
 * The per-client window keeps the same per-request-member form: a
 * client's window count is bounded by the per-client cap, so its
 * cardinality is inherently small.
 *
 * Results: {@see self::check()} returns 1 (allowed), 0 (per-client limit
 * reached) or -1 (global limit reached). {@see self::allow()} is the boolean
 * view for callers that do not distinguish.
 */
final class IssuanceRateLimiter
{
    // PSR-6 only requires keys up to 64 chars: 'kr_' + 60 hex = 63 chars.
    // The identity is already a keyed 256-bit HMAC, so truncating to 240
    // bits is more than sufficient.
    private const CACHE_KEY_PREFIX = 'kr_';

    /**
     * PSR-6 cache key for a client identity: 'kr_' + the first 60 hex chars
     * of the identity (which is already a keyed 256-bit HMAC — truncating to
     * 240 bits is more than sufficient). Total: 63 characters, within the
     * 64-character floor that PSR-6 requires implementations to support.
     */
    private static function cacheKey(string $identity): string
    {
        return self::CACHE_KEY_PREFIX.substr($identity, 0, 60);
    }

    /**
     * Atomic per-client + global sliding window (exact window-count audit
     * semantics):
     *   KEYS[1]  = per-client ZSET (one member per request; cardinality
     *              bounded by the per-client cap).
     *   KEYS[2]  = deployment-global ZSET (one exact-time member per
     *              admitted request; cardinality bounded by the global
     *              cap: at most globalMax members ever coexist, whatever
     *              the window length or request volume).
     *   ARGV[1]  = per-client max.
     *   ARGV[2]  = global max.
     *   ARGV[3]  = window in ms.
     *   ARGV[4]  = unique request id, the per-client member.
     *   ARGV[5]  = unique request id, the global member (the same
     *              per-admission id scheme as the per-client member).
     * Both ZSETs carry one member per admitted request, scored at the
     * exact admission millisecond (Redis TIME), so a member's timestamp
     * is exact and the window is exact at millisecond precision, never
     * bucketed to the second. Every admission prunes the members at
     * `<= now - window` with `ZREMRANGEBYSCORE`, then checks the caps
     * with `ZCARD`; the global count is the global cardinality, so no
     * count sum is needed. The admission is recorded with `ZADD now
     * <member>`. The per-admission work is O(pruned + ZCARD + `ZADD`),
     * bounded by the member count, which the caps bound.
     * Returns 1 when allowed, 0 when the per-client cap is full, -1 when
     * the global cap is full (both checked after pruning expired hits).
     */
    private const LIMIT_SCRIPT = <<<'LUA'
-- Rate limit: per-client + global exact-ms sliding window.
-- One member per admitted request on each ZSET, scored at the exact
-- admission millisecond; prune at <= now - window, refuse on ZCARD,
-- then ZADD the exact-time member.
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
local cutoff = now - tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', cutoff)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then return -1 end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('ZADD', KEYS[2], now, ARGV[5])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]) + 1000)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[3]) + 1000)
return 1
LUA;

    /**
     * Epoch-rotated variant of `LIMIT_SCRIPT` (3 keys): KEYS[1] = previous
     * client pseudonym, KEYS[2] = current client pseudonym, KEYS[3] = one
     * stable deployment-global ZSET with no client identity, which must
     * never be rotated or the global budget would silently become
     * per-client. The client identity is HMAC(secret, "kiwi-rate-v2|epoch|canonical-ip"), so
     * the same IP yields a different keyed pseudonym in every epoch: an
     * observer of old Redis snapshots cannot correlate one IP across time
     * periods. Checking the previous-epoch key keeps the per-client
     * sliding window exact across a rotation boundary. The global budget
     * is shared by all clients regardless of epoch and uses the same
     * exact-ms per-request structure as `LIMIT_SCRIPT`.
     */
    private const LIMIT_SCRIPT_ROTATED = <<<'LUA'
-- Rate limit: epoch-rotated per-client + global exact-ms sliding window.
-- Same exact-ms structure as the plain limiter; the per-client side
-- checks the previous + current epoch keys, the global ZSET is shared
-- and never rotated.
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
local cutoff = now - tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', cutoff)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', cutoff)
if redis.call('ZCARD', KEYS[1]) + redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[1]) then return 0 end
if redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[2]) then return -1 end
redis.call('ZADD', KEYS[2], now, ARGV[4])
redis.call('ZADD', KEYS[3], now, ARGV[5])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]) + 1000)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[3]) + 1000)
redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) + 1000)
return 1
LUA;

    /** @var array<string, list<float>> sliding-window hit timestamps, per process */
    private array $hits = [];

    /**
     * @param int                        $maxChallenges 0 disables the per-client limit.
     * @param int                        $windowSecs    sliding-window size in seconds.
     * @param CacheItemPoolInterface|null $pool          shared multi-process state.
     * @param \Closure|null              $now           epoch-seconds clock override for tests.
     * @param string                     $pepper        HMAC pepper for client identities.
     * @param \Redis|\Predis\Client|null $redis         when set, the atomic Redis backend
     *                                                  is used (per-client + global).
     * @param int                        $globalMax     0 disables the global limit
     *                                                  (enforced in the Redis backend).
     * @param string                     $namespace     deployment discriminator for the
     *                                                  Redis keys (sanitized to
     *                                                  [A-Za-z0-9_.-]).
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
        private readonly int $rateLimitRotationSecs = 0,
    ) {
        // A sliding window can cross at most ONE rotation boundary, so the
        // two-epoch (current + previous) accounting is only exact when the
        // rotation period is >= the window: otherwise live hits from epochs
        // older than (current - 1) silently vanish from the cap.
        if ($rateLimitRotationSecs > 0 && $rateLimitRotationSecs < $windowSecs) {
            throw new \InvalidArgumentException(
                'rate_limit_rotation_secs must be 0 or >= rate_limit_window_secs — '.
                'a rotation shorter than the window would drop live hits from older epochs'
            );
        }
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
     * @return int 1 = allowed, 0 = per-client limit reached, -1 = global
     *             limit reached
     */
    public function check(string $clientIp): int
    {
        if ($this->maxChallenges <= 0 && ($this->redis === null || $this->globalMax <= 0)) {
            return 1;
        }
        // Global-only mode short-circuits before any client identity is
        // computed or rotated: with maxChallenges == 0 and globalMax > 0
        // the deployment-wide budget is the only limit, so no per-client
        // pseudonym is ever derived and no client key is ever written
        // (even when rotation is enabled).
        if ($this->redis !== null && $this->maxChallenges <= 0 && $this->globalMax > 0) {
            return $this->checkRedisGlobalOnly();
        }
        // An unknown client IP must never bypass the limit: bucket it with
        // the other unidentifiable clients instead (conservative, shared
        // budget). The IP itself is never used as a key — only the HMAC.
        // The identity is derived from canonical IP bytes (inet_pton with
        // IPv4-mapped-IPv6 normalization), so two textual spellings of the
        // same address (e.g. "2001:db8::1" vs "2001:0db8:0:0:0:0:0:1")
        // produce the same pseudonym — matching the challenge binding tag.
        if ($clientIp === '') {
            $identity = 'unknown';
        } else {
            try {
                $identity = \KiwiCaptcha\Issuer::canonicalIpFamily($clientIp);
            } catch (\InvalidArgumentException) {
                $identity = 'unknown';
            }
        }

        if ($this->rateLimitRotationSecs > 0) {
            // Epoch-rotated pseudonym: HMAC(pepper, "kiwi-rate-v2|epoch|
            // canonical-ip"). The current and previous epoch identities
            // are both checked so the sliding window stays exact across a
            // rotation boundary; new hits are written to the current epoch
            // only. The same IP therefore yields different keys in
            // different epochs, so no correlation across time periods can
            // be derived from Redis keys.
            //
            // The epoch is derived from the Redis server clock when Redis
            // is the backend (a single TIME read): the Lua window pruning
            // uses Redis TIME, so using the same clock for the epoch keeps
            // both domains consistent around rotation boundaries even when
            // an application host's wall clock drifts.
            if ($this->redis !== null) {
                $now = $this->redisTimeSecs();
            } else {
                $now = $this->now();
            }
            $epoch = (int) floor($now / $this->rateLimitRotationSecs);
            $identityCur = $this->epochIdentity($identity, $epoch);
            $identityPrev = $this->epochIdentity($identity, $epoch - 1);

            if ($this->redis !== null) {
                return $this->checkRedisRotated($identityPrev, $identityCur);
            }

            return $this->maxChallenges > 0
                ? (int) ($this->pool !== null ? $this->allowSharedTwoEpoch($identityPrev, $identityCur) : $this->allowLocalTwoEpoch($identityPrev, $identityCur))
                : 1;
        }

        $key = hash_hmac('sha256', $identity, $this->pepper);

        if ($this->redis !== null) {
            if ($this->maxChallenges <= 0) {
                // Global-only: no client key or pseudonym is created at all
                // (data minimization: per-client control is explicitly
                // disabled, so no client identifier should exist).
                return $this->checkRedisGlobalOnly();
            }

            return $this->checkRedis($key);
        }

        return $this->maxChallenges > 0
            ? (int) ($this->pool !== null ? $this->allowShared($key) : $this->allowLocal($key))
            : 1;
    }

    private function epochIdentity(string $identity, int $epoch): string
    {
        return hash_hmac('sha256', 'kiwi-rate-v2|'.$epoch.'|'.$identity, $this->pepper);
    }

    private function checkRedisRotated(string $identityPrev, string $identityCur): int
    {
        // Only the client keys are epoch-rotated. The global key contains
        // no client identity and is shared by every client — rotating it
        // would silently turn the deployment-wide budget into per-client
        // budgets.
        $clientPrev = '{kiwi:rl:'.$this->namespace.'}:client:'.$identityPrev;
        $clientCur = '{kiwi:rl:'.$this->namespace.'}:client:'.$identityCur;
        $global = '{kiwi:rl:'.$this->namespace.'}:global';
        $windowMs = $this->windowSecs * 1000;
        $requestId = bin2hex(random_bytes(16));
        $clientMax = $this->maxChallenges > 0 ? $this->maxChallenges : \PHP_INT_MAX;
        $globalMax = $this->globalMax > 0 ? $this->globalMax : \PHP_INT_MAX;

        $result = $this->eval(self::LIMIT_SCRIPT_ROTATED, [$clientPrev, $clientCur, $global], [
            (string) $clientMax,
            (string) $globalMax,
            (string) $windowMs,
            $requestId,
            $requestId,
        ]);

        return (int) $result;
    }

    /**
     * Atomic global-only window: one stable deployment-global ZSET of
     * exact-time per-request members (KEYS[1]), used when the per-client
     * limit is disabled, so no client pseudonym ever exists in Redis.
     * The structure matches `LIMIT_SCRIPT`'s global key: prune at
     * `<= now - window`, refuse on `ZCARD >= max`, `ZADD` the exact-ms
     * member. One member per admitted request, so the cardinality is
     * bounded by the global cap, whatever the window length or request
     * volume.
     */
    private const LIMIT_SCRIPT_GLOBAL_ONLY = <<<'LUA'
-- Rate limit: global-only exact-ms sliding window.
-- One exact-time member per admitted request; prune at
-- <= now - window, refuse on ZCARD, then ZADD the exact-ms member.
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
local cutoff = now - tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return -1 end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) + 1000)
return 1
LUA;

    private function checkRedisGlobalOnly(): int
    {
        $globalKey = '{kiwi:rl:'.$this->namespace.'}:global';
        $windowMs = $this->windowSecs * 1000;
        $globalMax = $this->globalMax > 0 ? $this->globalMax : \PHP_INT_MAX;
        $requestId = bin2hex(random_bytes(16));

        $result = $this->eval(self::LIMIT_SCRIPT_GLOBAL_ONLY, [$globalKey], [
            (string) $globalMax,
            (string) $windowMs,
            $requestId,
        ]);

        return (int) $result;
    }

    /**
     * @param list<float> $a
     * @param list<float> $b
     *
     * @return list<float>
     */
    private function pruneTwo(array $a, array $b, float $now): array
    {
        $cutoff = $now - $this->windowSecs;

        return array_values(array_filter(array_merge($a, $b), static fn (float $ts): bool => $ts >= $cutoff));
    }

    private function allowLocalTwoEpoch(string $identityPrev, string $identityCur): bool
    {
        $now = $this->now();
        $hits = $this->pruneTwo($this->hits[$identityPrev] ?? [], $this->hits[$identityCur] ?? [], $now);
        if (\count($hits) >= $this->maxChallenges) {
            $windowSecs = $this->windowSecs;
            $this->hits[$identityPrev] = array_values(array_filter($this->hits[$identityPrev] ?? [], static fn (float $ts): bool => $ts >= $now - $windowSecs));
            $this->hits[$identityCur] = array_values(array_filter($this->hits[$identityCur] ?? [], static fn (float $ts): bool => $ts >= $now - $windowSecs));

            return false;
        }
        $this->hits[$identityCur][] = $now;

        return true;
    }

    private function allowSharedTwoEpoch(string $identityPrev, string $identityCur): bool
    {
        $now = $this->now();
        $cacheKeyPrev = self::cacheKey($identityPrev);
        $cacheKeyCur = self::cacheKey($identityCur);

        $itemPrev = $this->pool->getItem($cacheKeyPrev);
        $itemCur = $this->pool->getItem($cacheKeyCur);
        $prevHits = $this->prune($this->timestamps(\is_array($itemPrev->isHit() ? $itemPrev->get() : null) ? $itemPrev->get() : []), $now);
        $curHits = $this->prune($this->timestamps(\is_array($itemCur->isHit() ? $itemCur->get() : null) ? $itemCur->get() : []), $now);

        if (\count($prevHits) + \count($curHits) >= $this->maxChallenges) {
            // Retain the pruned state on denial — clearing it would let a
            // denied request reset the window and pass on the next call
            // (a deterministic every-other-request bypass).
            $itemPrev->set(['t' => $prevHits]);
            $itemPrev->expiresAfter($this->windowSecs + 1);
            $this->pool->save($itemPrev);
            $itemCur->set(['t' => $curHits]);
            $itemCur->expiresAfter($this->windowSecs + 1);
            $this->pool->save($itemCur);

            return false;
        }
        $curHits[] = $now;
        $itemCur->set(['t' => $curHits]);
        $itemCur->expiresAfter($this->windowSecs + 1);
        $this->pool->save($itemCur);

        return true;
    }

    private function checkRedis(string $identity): int
    {
        $clientKey = '{kiwi:rl:'.$this->namespace.'}:client:'.$identity;
        $globalKey = '{kiwi:rl:'.$this->namespace.'}:global';
        $windowMs = $this->windowSecs * 1000;
        $requestId = bin2hex(random_bytes(16));
        $clientMax = $this->maxChallenges > 0 ? $this->maxChallenges : \PHP_INT_MAX;
        $globalMax = $this->globalMax > 0 ? $this->globalMax : \PHP_INT_MAX;

        $result = $this->eval(self::LIMIT_SCRIPT, [$clientKey, $globalKey], [
            (string) $clientMax,
            (string) $globalMax,
            (string) $windowMs,
            $requestId,
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
        $cacheKey = self::cacheKey($key);

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
     * Read the Redis server clock (seconds since epoch). TIME is atomic and
     * shared by all workers: the rotation epoch and the Lua window pruning
     * must use the same clock so an application-host clock drift cannot
     * select a mismatched epoch right at a rotation boundary.
     */
    private function redisTimeSecs(): float
    {
        $time = $this->redis instanceof \Redis
            ? $this->redis->time()
            : $this->redis->time();

        if (!\is_array($time) || !isset($time[0]) || !\is_numeric($time[0])) {
            // Never fall back to the application clock for a Redis
            // rate-limit epoch: the rotated identity epoch and the Lua
            // sliding window need ONE Redis clock domain, and a malformed
            // TIME must fail closed (the caller converts this to the
            // structured 503) instead of silently re-introducing clock
            // disagreement at an identity-rotation boundary.
            throw new \RuntimeException('Redis TIME returned an invalid response');
        }

        return (float) $time[0];
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
