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
 *     consistent window and the enforcement is an exact gate. Redis is the
 *     only backend where the deployment-global cap is an exact distributed
 *     bound.
 *  2. PSR-6 pool (shared, best-effort): when a shared pool is configured but
 *     no Redis client exists, the per-client window is kept in the pool. The
 *     deployment-global window lives in ONE dedicated cache item
 *     (`kr_global`, shared by every client identity, distinct from the
 *     per-client `kr_`+60-hex keys). A PSR-6 pool cannot express an atomic
 *     read-modify-write, so the shared global window is cross-worker
 *     best-effort: concurrent requests racing the read-modify-write may
 *     briefly exceed the cap (N workers can admit up to ~N x cap in a
 *     race). It is a soft bound, never an exact distributed gate.
 *  3. Object memory (long-lived runtime only): the fallback when no pool
 *     is configured. The windows live in this object's fields, so they are
 *     exact for one persistent worker process (RoadRunner, Swoole, amphp
 *     or a single CLI process); N workers share no memory, so the
 *     deployment aggregate can approach N x cap. Under conventional
 *     PHP-FPM every request constructs a fresh limiter, so this mode is
 *     request-local: the windows provide no temporal limiting across
 *     requests at all.
 *
 * Lifecycle model: Redis is the exact distributed backend. A shared PSR-6
 * pool (`rate_limit_cache`) is the only no-Redis mode that survives across
 * requests, giving a cross-request best-effort window (never an exact
 * distributed gate: concurrent requests racing the non-atomic
 * read-modify-write may briefly exceed the cap). The object-memory mode is
 * long-lived-runtime-only: it provides temporal limiting only inside a
 * persistent worker or a single CLI process. Under conventional PHP-FPM
 * the services are rebuilt per request, so the object-memory windows are
 * per-request and provide no temporal limiting across requests;
 * production temporal limiting without Redis requires a genuinely
 * persistent or shared PSR-6 pool.
 *
 * Degradation ladder for the deployment-global cap: exact distributed
 * (Redis) -> shared best-effort (PSR-6) -> object-memory exact for one
 * persistent worker. The global cap is enforced on ALL backends: without
 * Redis the limiter keeps a real global window (the shared `kr_global`
 * item when a pool is configured, the process-local list otherwise)
 * instead of disabling the cap. `allow_nonredis_rate_limit_fallback`
 * therefore means "long-lived-runtime-only object window / shared
 * best-effort window", never "no temporal limit at all".
 *
 * Transactional fallback decisions: on the non-Redis backends each request
 * is ONE read-then-decide pass over the per-client and global windows —
 * prune and read both, deny (0 or -1) without writing anything, or admit
 * and commit both hits. A denial therefore never consumes the caller's
 * own allowance (a victim refused during global saturation keeps their
 * personal window untouched) and can never reset a window (pruning is
 * idempotent: the next read re-prunes with a newer clock). The object-
 * memory decision is exact; a generic PSR-6 pool cannot make the two item
 * writes atomic across workers, so inter-worker races on the
 * read-modify-write remain the documented best-effort weakness (the
 * per-request semantics stay transactional).
 *
 * Privacy: raw client IPs are never stored. Every key (Redis, PSR-6 and
 * object memory) is a peppered HMAC of the IP, `hash_hmac('sha256', $ip,
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
     * PSR-6 cache key for the deployment-global window: a fixed item shared
     * by every client identity (the global cap is deployment-wide, not
     * per-client). It must stay distinct from the per-client keys
     * ('kr_' + 60 hex chars): this literal contains non-hex characters, so
     * it can never collide with a client-HMAC key, and it must never be
     * rotated (the global budget is rotation-independent by design).
     */
    private const GLOBAL_CACHE_KEY = 'kr_global';

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
     * Object-memory GC cadence (non-rotated mode): every this many local
     * admissions the limiter sweeps the per-identity hit map once,
     * dropping buckets whose latest hit has slid out of the window, so
     * abandoned identities cannot keep their buckets for the process
     * lifetime. Amortized O(1) per admission; the sweep only ever
     * removes window-expired identities, so no decision can change.
     */
    private const OBJECT_MEMORY_GC_INTERVAL = 256;

    /**
     * Admissions since the last object-memory GC sweep (non-rotated mode
     * only): the bounded cadence driver of the per-identity map sweep
     * `OBJECT_MEMORY_GC_INTERVAL`. The rotated path is
     * epoch-GC'd on every check and the deployment-global window is a
     * single list pruned per check, so only the non-rotated per-identity
     * map needs the admission counter.
     */
    private int $localAdmissionsSinceGc = 0;

    /**
     * Rotated object-memory state: epoch -> identity-key -> hit timestamps.
     * Only the current and the previous epoch can intersect the sliding
     * window (the constructor enforces rotationSecs >= windowSecs), so every
     * older epoch bucket is lazily garbage-collected on the next rotated
     * check, keeping this map bounded in long-lived runtimes.
     *
     * @var array<int, array<string, list<float>>>
     */
    private array $hitsByEpoch = [];

    /** @var list<float> deployment-global sliding-window hit timestamps, per process */
    private array $globalHits = [];

    /**
     * @param int                        $maxChallenges 0 disables the per-client limit.
     * @param int                        $windowSecs    sliding-window size in seconds.
     * @param CacheItemPoolInterface|null $pool          shared multi-process state.
     * @param \Closure|null              $now           epoch-seconds clock override for tests.
     * @param string                     $pepper        HMAC pepper for client identities.
     * @param \Redis|\Predis\Client|null $redis         when set, the atomic Redis backend
     *                                                  is used (per-client + global).
     * @param int                        $globalMax     0 disables the global limit
     *                                                  (enforced on all backends:
     *                                                  Redis, shared PSR-6 and
     *                                                  in-memory).
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
        // Everything disabled: no limit applies at all.
        if ($this->maxChallenges <= 0 && $this->globalMax <= 0) {
            return 1;
        }
        // Global-only mode short-circuits before any client identity is
        // computed or rotated: with maxChallenges == 0 and globalMax > 0
        // the deployment-wide budget is the only limit, so no per-client
        // pseudonym is ever derived and no client key is ever written
        // (even when rotation is enabled — the global window is
        // rotation-independent by design).
        if ($this->maxChallenges <= 0) {
            if ($this->redis !== null) {
                return $this->checkRedisGlobalOnly();
            }

            // Without Redis the global-only budget is still enforced: the
            // shared PSR-6 item when a pool is configured, the
            // process-local window otherwise (both best-effort per
            // deployment — see the class docblock).
            return $this->checkLocalGlobalOnly();
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

            // Non-Redis fallback: ONE transactional per-request decision
            // over the per-client and deployment-global windows (deny = 0
            // when the client is full, deny = -1 when the global is full),
            // mirroring the Redis script's check order. maxChallenges > 0
            // is guaranteed here (global-only short-circuited above).
            return $this->pool !== null
                ? $this->checkSharedTwoEpoch($identityPrev, $identityCur)
                : $this->checkLocalTwoEpoch($identityPrev, $identityCur);
        }

        $key = hash_hmac('sha256', $identity, $this->pepper);

        if ($this->redis !== null) {
            return $this->checkRedis($key);
        }

        // Non-Redis fallback: ONE transactional per-request decision over
        // the per-client and deployment-global windows (deny = 0 when the
        // client is full, deny = -1 when the global is full), mirroring
        // the Redis script's check order.
        return $this->pool !== null ? $this->checkShared($key) : $this->checkLocal($key);
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
     * Global-only window without Redis (maxChallenges == 0, globalMax > 0):
     * the deployment-global budget is the only limit, so no client identity
     * is ever computed or written. The window lives in the shared PSR-6
     * item when a pool is configured, otherwise in the process-local list;
     * it is rotation-independent by design (the global budget is shared by
     * all clients and epochs). A denial writes nothing: the pruned state
     * is idempotent (the next read re-prunes with a newer clock), so
     * dropping the write can never reset the window.
     *
     * @return int 1 = allowed, -1 = global limit reached
     */
    private function checkLocalGlobalOnly(): int
    {
        $now = $this->now();

        if ($this->pool !== null) {
            $globalItem = $this->pool->getItem(self::GLOBAL_CACHE_KEY);
            $globalState = $globalItem->isHit() ? $globalItem->get() : null;
            $globalHits = $this->prune(\is_array($globalState) ? $this->timestamps($globalState) : [], $now);

            if (\count($globalHits) >= $this->globalMax) {
                return -1;
            }
            $globalHits[] = $now;
            $this->saveWindow($globalItem, $globalHits);

            return 1;
        }

        $globalHits = $this->prune($this->globalHits, $now);

        if (\count($globalHits) >= $this->globalMax) {
            return -1;
        }
        $globalHits[] = $now;
        $this->globalHits = $globalHits;

        return 1;
    }

    /**
     * Transactional combined fallback decision (no rotation, in-memory):
     * read and prune the per-client window, then read and prune the
     * deployment-global window, in ONE pass per request. A denied request
     * writes nothing — neither the client window nor the global window —
     * so a victim refused by global saturation never consumes their own
     * allowance. A denial can never reset a window either: pruning is
     * idempotent, and the next read re-prunes with a newer clock.
     * An admitted request commits both hits. The in-process decision is
     * exact. Return codes match the Redis script: 1 = allowed, 0 =
     * per-client full, -1 = global full.
     */
    private function checkLocal(string $key): int
    {
        $now = $this->now();
        $hits = $this->prune($this->hits[$key] ?? [], $now);

        if (\count($hits) >= $this->maxChallenges) {
            return 0;
        }

        $globalHits = [];
        if ($this->globalMax > 0) {
            $globalHits = $this->prune($this->globalHits, $now);
            if (\count($globalHits) >= $this->globalMax) {
                return -1;
            }
        }

        $hits[] = $now;
        $this->hits[$key] = $hits;
        $globalHits[] = $now;
        $this->globalHits = $globalHits;

        // Bounded object-memory GC (long-lived-runtime hygiene): every
        // `OBJECT_MEMORY_GC_INTERVAL`-th local admission sweeps the
        // per-identity map once, dropping buckets whose latest hit has
        // slid out of the window. Amortized O(1) per admission; the
        // sweep never touches live windows. Only the non-rotated path
        // needs it: the rotated path is epoch-GC'd on every check and
        // the global window is a single list pruned per check. The
        // current client's bucket was just written with $now, so it is
        // never swept.
        if (++$this->localAdmissionsSinceGc % self::OBJECT_MEMORY_GC_INTERVAL === 0) {
            $this->sweepStaleLocalHits($now);
        }

        return 1;
    }

    /**
     * Sweep the non-rotated object-memory hit map once: unset every
     * identity bucket whose latest hit is older than now - windowSecs.
     * Uses the same strict cutoff as {@see self::prune()}, so a bucket
     * whose last hit sits exactly at the boundary is dead. Runs at the
     * `OBJECT_MEMORY_GC_INTERVAL` cadence from the non-rotated local
     * admit path only; decisions are unaffected, since only
     * window-expired identities are removed.
     */
    private function sweepStaleLocalHits(float $now): void
    {
        $cutoff = $now - $this->windowSecs;
        foreach ($this->hits as $key => $hits) {
            if (max($hits) <= $cutoff) {
                unset($this->hits[$key]);
            }
        }
    }

    /**
     * Transactional combined fallback decision (no rotation, shared PSR-6):
     * same read-then-decide flow as {@see self::checkLocal()}, with the
     * windows held in the pool. A denied request saves neither item; an
     * admitted request saves both (the client item and the `kr_global`
     * item). The per-request semantics are transactional, but a generic
     * PSR-6 pool cannot make the two item writes atomic across workers:
     * concurrent requests racing the read-modify-write may briefly exceed
     * the caps (best-effort, documented in the class docblock). Only Redis
     * is an exact distributed gate.
     */
    private function checkShared(string $key): int
    {
        $now = $this->now();

        $item = $this->pool->getItem(self::cacheKey($key));
        $state = $item->isHit() ? $item->get() : null;
        $hits = $this->prune(\is_array($state) ? $this->timestamps($state) : [], $now);

        if (\count($hits) >= $this->maxChallenges) {
            return 0;
        }

        if ($this->globalMax > 0) {
            $globalItem = $this->pool->getItem(self::GLOBAL_CACHE_KEY);
            $globalState = $globalItem->isHit() ? $globalItem->get() : null;
            $globalHits = $this->prune(\is_array($globalState) ? $this->timestamps($globalState) : [], $now);

            if (\count($globalHits) >= $this->globalMax) {
                return -1;
            }

            $hits[] = $now;
            $this->saveWindow($item, $hits);

            $globalHits[] = $now;
            $this->saveWindow($globalItem, $globalHits);

            return 1;
        }

        $hits[] = $now;
        $this->saveWindow($item, $hits);

        return 1;
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

        return array_values(array_filter(array_merge($a, $b), static fn (float $ts): bool => $ts > $cutoff));
    }

    /**
     * Transactional combined fallback decision (epoch-rotated, object
     * memory): the previous- and current-epoch pseudonym windows are read,
     * pruned and merged, then the deployment-global window is read and
     * pruned, in ONE pass per request. Same deny-writes-nothing semantics
     * as {@see self::checkLocal()}: a global-saturation denial never
     * consumes the client's allowance in either epoch, and no denial can
     * reset any window. New hits are written to the current epoch only;
     * the global window is shared and never rotated.
     */
    private function checkLocalTwoEpoch(string $identityPrev, string $identityCur): int
    {
        $now = $this->now();
        // Lazy epoch GC: only the current and the previous epoch can
        // intersect the sliding window (rotationSecs >= windowSecs is
        // enforced in the constructor), so every bucket from an epoch
        // older than (current - 1) is dropped on this check. In a
        // long-lived runtime the map therefore never grows with
        // historical admitted traffic.
        $epoch = (int) floor($now / $this->rateLimitRotationSecs);
        foreach (array_keys($this->hitsByEpoch) as $storedEpoch) {
            if ($storedEpoch < $epoch - 1) {
                unset($this->hitsByEpoch[$storedEpoch]);
            }
        }
        $hits = $this->pruneTwo(
            $this->hitsByEpoch[$epoch - 1][$identityPrev] ?? [],
            $this->hitsByEpoch[$epoch][$identityCur] ?? [],
            $now,
        );

        if (\count($hits) >= $this->maxChallenges) {
            return 0;
        }

        $globalHits = [];
        if ($this->globalMax > 0) {
            $globalHits = $this->prune($this->globalHits, $now);
            if (\count($globalHits) >= $this->globalMax) {
                return -1;
            }
        }

        $this->hitsByEpoch[$epoch][$identityCur][] = $now;
        $globalHits[] = $now;
        $this->globalHits = $globalHits;

        return 1;
    }

    /**
     * Transactional combined fallback decision (epoch-rotated, shared
     * PSR-6): same read-then-decide flow as
     * {@see self::checkLocalTwoEpoch()} with the windows in the pool. A
     * denied request saves NO item (neither the previous- nor the
     * current-epoch client item, nor the `kr_global` item); an admitted
     * request saves the current-epoch client item and the global item.
     * Inter-worker races on the non-atomic read-modify-write are the
     * documented best-effort weakness of any generic PSR-6 pool.
     */
    private function checkSharedTwoEpoch(string $identityPrev, string $identityCur): int
    {
        $now = $this->now();

        $itemPrev = $this->pool->getItem(self::cacheKey($identityPrev));
        $itemCur = $this->pool->getItem(self::cacheKey($identityCur));
        $prevState = $itemPrev->isHit() ? $itemPrev->get() : null;
        $curState = $itemCur->isHit() ? $itemCur->get() : null;
        $prevHits = $this->prune(\is_array($prevState) ? $this->timestamps($prevState) : [], $now);
        $curHits = $this->prune(\is_array($curState) ? $this->timestamps($curState) : [], $now);

        if (\count($prevHits) + \count($curHits) >= $this->maxChallenges) {
            return 0;
        }

        if ($this->globalMax > 0) {
            $globalItem = $this->pool->getItem(self::GLOBAL_CACHE_KEY);
            $globalState = $globalItem->isHit() ? $globalItem->get() : null;
            $globalHits = $this->prune(\is_array($globalState) ? $this->timestamps($globalState) : [], $now);

            if (\count($globalHits) >= $this->globalMax) {
                return -1;
            }

            $curHits[] = $now;
            $this->saveWindow($itemCur, $curHits);

            $globalHits[] = $now;
            $this->saveWindow($globalItem, $globalHits);

            return 1;
        }

        $curHits[] = $now;
        $this->saveWindow($itemCur, $curHits);

        return 1;
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

    /**
     * Persist a window's hit timestamps into one cache item (shared by
     * every admit path) with the item TTL one second past the window.
     *
     * Fail closed: PSR-6 permits save() to return false without throwing,
     * and a silent false would let an admit decision stand with its
     * accounting never persisted. Any save returning false on an admit
     * path raises {@see RateLimitStorageException}; the challenge
     * controller converts it to the same structured 503 as a Redis
     * outage, so an admit is never reported allowed after a failed
     * backend write. Deny paths write nothing and never reach this
     * method. Partial charging (one of two required items saved, then
     * this exception) is acceptable and conservative: the next read
     * re-prunes with a newer clock, so the leftover hit can never be
     * double-counted.
     *
     * @param list<float> $hits
     *
     * @throws RateLimitStorageException when the pool reports the save failed
     */
    private function saveWindow(\Psr\Cache\CacheItemInterface $item, array $hits): void
    {
        $item->set(['t' => $hits]);
        $item->expiresAfter($this->windowSecs + 1);
        if ($this->pool->save($item) === false) {
            throw new RateLimitStorageException('PSR-6 rate-limit window save returned false; refusing the admit');
        }
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
        // Strictly-greater cutoff, matching Redis's inclusive
        // `ZREMRANGEBYSCORE ... -inf (now - window)`: a hit at the exact
        // boundary instant now - window has slid out of the window and is
        // pruned. An inclusive (>=) predicate would keep it for the
        // boundary instant and diverge from the Redis window.
        $cutoff = $now - $this->windowSecs;

        return array_values(array_filter($hits, static fn (float $ts): bool => $ts > $cutoff));
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
