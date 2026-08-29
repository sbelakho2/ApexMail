<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\VerificationAdmissionGate;

/**
 * Redis-backed Argon2id admission gate implementing the tokenized-lease
 * design of the audit.
 *
 * Caps concurrent Argon2id verifications across all PHP-FPM workers sharing
 * the Redis instance. Implements the core's
 * {@see \KiwiCaptcha\VerificationAdmissionGate}: acquire() returns an opaque
 * lease token, release() removes exactly that token. Stale releases cannot
 * remove a newer lease: a lease is a unique member of a sorted set, so
 * releasing an expired/double-released token is a no-op (ZREM of an absent
 * member) and can never touch a different token's slot.
 *
 * Each lease is a sorted-set member scored at its expiry (now + `LEASE_MS`).
 * The acquire script prunes expired leases first (`ZREMRANGEBYSCORE` up to
 * `now`; a lease whose score is in the past is dead), then admits when the
 * live count is below the cap. A worker that crashes while holding a lease
 * never releases it, but its lease expires after `LEASE_MS` and is reaped by
 * the next acquire, with no watchdog counter to drift and no DECR race.
 *
 * Key: `kiwicaptcha:argon2:leases:<namespace>`, one lease set per
 * deployment; the namespace is sanitized to [A-Za-z0-9_.-] (defaults to
 * 'default' when empty).
 *
 * A `maxConcurrent` <= 0 disables the cap: acquire() returns the sentinel
 * token 'disabled' and release() no-ops; the verifier's lease lifecycle
 * stays uniform.
 */
final class RedisAdmissionSemaphore implements VerificationAdmissionGate
{
    /** Default lease lifetime in ms; expired leases are reaped by the next acquire. */
    private const DEFAULT_LEASE_MS = 45_000;

    /**
     * Atomic acquire with the bounded saturation-pressure counter and the
     * per-scope concentration cap:
     *   KEYS[1]  = lease set key (global).
     *   KEYS[2]  = saturation-pressure counter key.
     *   KEYS[3]  = per-scope lease set key. The global lease set key is
     *              declared in its place when there is no scope (a real
     *              same-slot key, never an empty placeholder), gated by
     *              ARGV[6]. An empty string has its own hash slot and
     *              would break the EVAL on Cluster.
     *   ARGV[1]  = max concurrent leases (global cap).
     *   ARGV[2]  = lease lifetime in ms (LEASE_MS).
     *   ARGV[3]  = unique lease token.
     *   ARGV[4]  = saturation-pressure cap (argon2_saturation_pressure_cap).
     *   ARGV[5]  = per-scope concentration cap (argon2_max_per_tenant).
     *   ARGV[6]  = 1 when KEYS[3] is a live per-scope set, else 0.
     *
     * Lease semantics are unchanged: expired leases are pruned, the lease
     * is granted when a slot is free. The per-scope set is checked in
     * addition to the global cap: a scope whose own set is full is refused
     * even when the global set has room. The per-scope cap is a
     * concentration cap: it prevents one busy scope from monopolizing the
     * shared capacity, it never reserves a specific share for any tenant.
     * The global cap always wins (the deployment-wide memory invariant).
     * Admission is immediate and non-blocking: a refused contender is
     * never queued, polled or later admitted. A granted caller is a
     * served contender, so the saturation counter is decremented (floored
     * at 0) in the same script. When a cap is saturated the contender is
     * refused right away and the counter is incremented with the lease
     * lifetime's TTL. Once the counter exceeds the saturation-pressure
     * cap, strictly after the post-INCR value and the boundary value
     * equal to the cap does not trip, the script returns the
     * distinguishable capacity sentinel -1 after removing the
     * contender's own entry. The gauge can never grow unboundedly under
     * a saturation storm, and acquire() can map the over-cap refusal to
     * its explicit fast-fail CapacityExceeded path, observable through
     * {@see self::lastAcquireFastFailed()}. The lease contract is
     * unchanged: null, no slot held, no counter residue. The counter
     * stays global, one shared gauge regardless of which cap refused.
     * Returns 1 when the lease was granted, 0 when refused by a cap, -1
     * when refused by the saturation-pressure bound.
     */
    private const ACQUIRE_SCRIPT = <<<'LUA'
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
local has_scope = tonumber(ARGV[6]) == 1
local scope_cap = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if has_scope and scope_cap > 0 then
    redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
end
local admitted = false
if redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[1]) then
    if not has_scope or scope_cap <= 0 or redis.call('ZCARD', KEYS[3]) < scope_cap then
        redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[3])
        redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2])*2)
        if has_scope and scope_cap > 0 then
            redis.call('ZADD', KEYS[3], now + tonumber(ARGV[2]), ARGV[3])
            redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[2])*2)
        end
        admitted = true
    end
end
if admitted then
    local waiters = tonumber(redis.call('GET', KEYS[2]) or '0')
    if waiters > 0 then redis.call('DECR', KEYS[2]) end
    return 1
end
local waiters = redis.call('INCR', KEYS[2])
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[2])*2)
if waiters > tonumber(ARGV[4]) then
    redis.call('DECR', KEYS[2])
    return -1
end
return 0
LUA;

    /**
     * Atomic release (exact audit semantics): removes exactly the lease
     * token from the global set and, when the token carries a per-scope
     * suffix, from that scope's set. ZREM of an absent member is a no-op,
     * so stale releases cannot remove a newer lease.
     *
     * KEYS[1] = lease set key (global).
     * KEYS[2] = per-scope lease set key; the global lease set key is
     *           declared in its place when there is no scope (a real
     *           same-slot key, never an empty placeholder).
     * ARGV[1] = lease token to release.
     * ARGV[2] = 1 when KEYS[2] is a live per-scope set, else 0.
     */
    private const RELEASE_SCRIPT = <<<'LUA'
-- Admission release with per-scope lease removal
local removed = redis.call('ZREM', KEYS[1], ARGV[1])
if tonumber(ARGV[2]) == 1 then
    redis.call('ZREM', KEYS[2], ARGV[1])
end
return removed
LUA;

    /**
     * Atomic-live usage: one script, TIME -> now_ms ->
     * `ZREMRANGEBYSCORE` '-inf' now -> ZCARD. Mirrors the acquire path's
     * pruning, so the returned count is the live lease count: expired
     * leases are reaped exactly as the next acquire would reap them, where
     * ZCARD alone would overcount while leases sit un-reaped between
     * acquires.
     *
     * KEYS[1] = lease set key
     */
    private const USAGE_SCRIPT = <<<'LUA'
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
return redis.call('ZCARD', KEYS[1])
LUA;

    private readonly string $key;

    /** The saturation-pressure counter key — same hash tag as the lease set (Cluster safe). */
    private readonly string $waitersKey;

    /**
     * @var bool whether the last acquire() was refused by the
     *           saturation-pressure fast-fail (the script's -1 sentinel:
     *           the waiters gauge was already at the cap when this
     *           contender was refused). Observability for callers and
     *           telemetry — the lease contract is identical either way
     *           (null, no slot held, no counter residue); the flag
     *           distinguishes "ordinary cap-full, retry soon" from
     *           "saturation storm, back off harder".
     */
    private bool $lastAcquireFastFailed = false;

    /**
     * @param \Redis|\Predis\Client $client                 Redis client (phpredis or
     *                                                      Predis; the same clients
     *                                                      RedisStorage accepts, and
     *                                                      the bundle itself has no
     *                                                      hard dependency on either).
     * @param int                   $maxConcurrent          cap; <= 0 disables the cap.
     * @param string                $namespace              per-deployment discriminator
     *                                                      (sanitized to
     *                                                      [A-Za-z0-9_.-]).
     * @param int                   $saturationPressureCap  bounded saturation-pressure
     *                                                      counter
     *                                                      (argon2_saturation_pressure_cap,
     *                                                      >= 1): when a cap is
     *                                                      saturated and the
     *                                                      counter exceeds it,
     *                                                      acquire() refuses
     *                                                      immediately through
     *                                                      the explicit
     *                                                      fast-fail path (the
     *                                                      script's -1
     *                                                      sentinel; see
     *                                                      {@see self::lastAcquireFastFailed()}).
     *                                                      The counter is a
     *                                                      gauge, never a
     *                                                      queue: admission is
     *                                                      immediate and
     *                                                      non-blocking.
     * @param int                   $maxPerScope            per-scope concentration cap
     *                                                      (argon2_max_per_tenant,
     *                                                      >= 1): each scope string
     *                                                      has its own lease set
     *                                                      checked in addition to the
     *                                                      global cap, so one busy
     *                                                      scope cannot monopolize the
     *                                                      shared capacity.
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly int $maxConcurrent,
        string $namespace = 'default',
        private readonly int $leaseMs = self::DEFAULT_LEASE_MS,
        private readonly int $saturationPressureCap = 64,
        private readonly int $maxPerScope = 8,
    ) {
        if ($leaseMs < 1_000) {
            throw new \InvalidArgumentException('leaseMs must be >= 1000');
        }
        if ($saturationPressureCap < 1) {
            throw new \InvalidArgumentException('saturationPressureCap must be >= 1');
        }
        if ($maxPerScope < 1) {
            throw new \InvalidArgumentException('maxPerScope must be >= 1');
        }
        $suffix = preg_replace('/[^A-Za-z0-9_.-]/', '_', $namespace) ?: 'default';
        $this->key = 'kiwicaptcha:argon2:leases:'.$suffix;
        // The saturation counter must live in the same hash slot as the
        // lease set (one EVAL script touches both keys), so it is
        // hash-tagged with the lease key's tag family.
        $this->waitersKey = '{kiwicaptcha:argon2:leases:'.$suffix.'}:sem:waiters';
    }

    /**
     * Whether the most recent acquire() was refused by the
     * saturation-pressure bound (the waiters gauge already at
     * argon2_saturation_pressure_cap when the contender arrived) rather
     * than by an ordinary cap refusal. Both refusals return null — this
     * flag is the distinguishable capacity signal the acquire script's -1
     * sentinel feeds, so callers and telemetry can tell a saturation
     * storm (shed load, back off) from ordinary cap contention (retry
     * soon). Reset by every acquire().
     */
    public function lastAcquireFastFailed(): bool
    {
        return $this->lastAcquireFastFailed;
    }

    /**
     * Acquire an Argon2id admission slot. Immediate and non-blocking: on
     * saturation (the global or per-scope cap is full) the method returns
     * null right away and the "waiters" counter records the
     * saturation-pressure spike. When that counter is already AT the
     * saturation-pressure cap, the contender trips the fast-fail: the
     * script returns its distinguishable sentinel (-1) after removing
     * the contender's own counter entry. `acquire()` maps it to the
     * explicit CapacityExceeded path, null, no slot held, no counter
     * residue, surfacing the distinction through
     * {@see self::lastAcquireFastFailed()}. A rejected request is never
     * queued, polled or later admitted: the counter is a gauge, not a
     * queue.
     *
     * @param string|null $scope the scope string (the challenge's scope) for
     *                           the per-scope concentration cap: the scope's
     *                           own lease set ({kiwicaptcha:argon2:leases:
     *                           <ns>}:<sha256(scope)>) is checked against
     *                           argon2_max_per_tenant in addition to the
     *                           global cap. Null = no per-scope attribution,
     *                           only the global cap applies; the bundle's
     *                           RequestScopeAdmissionGate transports the
     *                           scope through the request attribute that the
     *                           native validator and the Siteverify
     *                           endpoint stamp before verification (an
     *                           unscoped acquire would silently skip the
     *                           per-scope cap).
     */
    public function acquire(?string $scope = null): ?string
    {
        if ($this->maxConcurrent <= 0) {
            return 'disabled';
        }
        $token = bin2hex(random_bytes(16));
        $scopeKey = '';
        $hasScope = false;
        if ($scope !== null && $scope !== '') {
        // Per-scope set: {kiwicaptcha:argon2:leases:<ns>}:<sha256(scope)}
        // — hash-tagged with the same family as the saturation counter
        // (Cluster safe). The scope is hashed, never sanitized: a
        // lossy sanitization would collapse distinct legitimate scopes
        // (tenant:a and tenant_a share one per-tenant cap, letting
        // one monopolize the other's share) and would leak scope names
        // into the key. The token carries the hashed scope suffix so
        // release() can remove the lease from both sets.
            $scopeSuffix = hash('sha256', $scope);
            $scopeKey = '{'.$this->key.'}:'.$scopeSuffix;
            $token .= '.'.$scopeSuffix;
            $hasScope = true;
        }
        $result = (int) $this->eval(
            self::ACQUIRE_SCRIPT,
            [$this->key, $this->waitersKey, $scopeKey !== '' ? $scopeKey : $this->key],
            [(string) $this->maxConcurrent, (string) $this->leaseMs, $token, (string) $this->saturationPressureCap, (string) $this->maxPerScope, $hasScope ? '1' : '0'],
        );

        if ($result === 1) {
            $this->lastAcquireFastFailed = false;

            return $token;
        }
        if ($result === -1) {
            // Saturation-pressure fast-fail: the waiters gauge was already
            // at the cap when this contender arrived, so the script
            // removed the contender's own entry (the gauge stays at the
            // cap, never growing) and returned the distinguishable
            // sentinel. The CapacityExceeded path: refuse immediately,
            // hold no lease slot, leave no counter residue — the caller
            // surfaces CapacityExceeded (the captcha violation / 429) and
            // telemetry can distinguish the storm from ordinary
            // contention through lastAcquireFastFailed().
            $this->lastAcquireFastFailed = true;

            return null;
        }
        $this->lastAcquireFastFailed = false;

        return null;
    }

    public function release(string $lease): void
    {
        if ($lease === 'disabled') {
            return;
        }
        // A scoped lease token carries ".<sha256(scope)>" after the hex
        // nonce; the hashed scope suffix rebuilds the per-scope set key.
        $scopeKey = '';
        $hasScope = false;
        $sep = strpos($lease, '.');
        if ($sep !== false) {
            $scope = substr($lease, $sep + 1);
            if ($scope !== '') {
                $scopeKey = '{'.$this->key.'}:'.$scope;
                $hasScope = true;
            }
        }
        $this->eval(self::RELEASE_SCRIPT, [$this->key, $scopeKey !== '' ? $scopeKey : $this->key], [$lease, $hasScope ? '1' : '0']);
    }

    /** The configured concurrency cap (0 = disabled). */
    public function capacity(): int
    {
        return $this->maxConcurrent;
    }

    /**
     * Live number of held leases, atomic TIME + prune + ZCARD in one Lua
     * script, so the count is live: expired leases are reaped exactly as
     * the next acquire would reap them. 0 when the cap is disabled
     * (genuinely zero leases — the sentinel path never touches Redis).
     *
     * A Throwable from the backend (connection failure, script error)
     * returns null, "unknown", never 0: 0 means the gate is verifiably
     * empty, null means the gate cannot be measured. The caller (the
     * resource-pressure provider) treats null conservatively as saturated.
     * Read-side telemetry — never breaks the caller.
     */
    public function usage(): ?int
    {
        if ($this->maxConcurrent <= 0) {
            return 0;
        }
        try {
            return (int) $this->eval(self::USAGE_SCRIPT, [$this->key], []);
        } catch (\Throwable) {
            return null;
        }
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
