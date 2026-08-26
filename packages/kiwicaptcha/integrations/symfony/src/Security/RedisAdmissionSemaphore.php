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
     * Atomic acquire with the bounded waiters guard and the per-scope
     * budget:
     *   KEYS[1]  = lease set key (global).
     *   KEYS[2]  = waiters counter key.
     *   KEYS[3]  = per-scope lease set key. The global lease set key is
     *              declared in its place when there is no scope (a real
     *              same-slot key, never an empty placeholder), gated by
     *              ARGV[6]. An empty string has its own hash slot and
     *              would break the EVAL on Cluster.
     *   ARGV[1]  = max concurrent leases (global cap).
     *   ARGV[2]  = lease lifetime in ms (LEASE_MS).
     *   ARGV[3]  = unique lease token.
     *   ARGV[4]  = max waiters (argon2_max_waiters).
     *   ARGV[5]  = per-scope cap (argon2_max_per_tenant).
     *   ARGV[6]  = 1 when KEYS[3] is a live per-scope set, else 0.
     *
     * Lease semantics are unchanged: expired leases are pruned, the lease
     * is granted when a slot is free. The per-scope set is checked in
     * addition to the global cap: a scope whose own set is full is refused
     * even when the global set has room (per-tenant fairness: one busy
     * scope can never starve the others' Argon budget). The global cap
     * always wins (the deployment-wide memory invariant). A granted caller
     * is a served waiter, so the waiters counter is decremented (floored
     * at 0) in the same script. When a cap is saturated the caller would
     * block behind the gate: the global waiters counter is incremented
     * with the lease lifetime's TTL. Once the waiter count exceeds
     * maxWaiters, the acquire returns null immediately, the caller refused
     * without queueing (CapacityExceeded surfaces as the 429/violation),
     * and its waiter entry is removed in the same script. The counter can
     * therefore never grow unboundedly under a saturation storm. The
     * waiters guard stays global, one shared bounded queue regardless of
     * which cap refused. Returns 1 when the lease was granted, 0 when
     * refused.
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
    return 0
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

    /** The waiters counter key — same hash tag as the lease set (Cluster safe). */
    private readonly string $waitersKey;

    /**
     * @param \Redis|\Predis\Client $client       Redis client (phpredis or
     *                                            Predis; the same clients
     *                                            RedisStorage accepts, and
     *                                            the bundle itself has no
     *                                            hard dependency on either).
     * @param int                   $maxConcurrent cap; <= 0 disables the cap.
     * @param string                $namespace     per-deployment discriminator
     *                                             (sanitized to
     *                                             [A-Za-z0-9_.-]).
     * @param int                   $maxWaiters    bounded waiters guard
     *                                             (argon2_max_waiters, >= 1):
     *                                             when a cap is saturated and
     *                                             the waiter count exceeds it,
     *                                             acquire() refuses immediately
     *                                             instead of queueing.
     * @param int                   $maxPerScope   per-scope budget
     *                                             (argon2_max_per_tenant, >= 1):
     *                                             each scope string has its
     *                                             own lease set checked in
     *                                             addition to the global cap.
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly int $maxConcurrent,
        string $namespace = 'default',
        private readonly int $leaseMs = self::DEFAULT_LEASE_MS,
        private readonly int $maxWaiters = 64,
        private readonly int $maxPerScope = 8,
    ) {
        if ($leaseMs < 1_000) {
            throw new \InvalidArgumentException('leaseMs must be >= 1000');
        }
        if ($maxWaiters < 1) {
            throw new \InvalidArgumentException('maxWaiters must be >= 1');
        }
        if ($maxPerScope < 1) {
            throw new \InvalidArgumentException('maxPerScope must be >= 1');
        }
        $suffix = preg_replace('/[^A-Za-z0-9_.-]/', '_', $namespace) ?: 'default';
        $this->key = 'kiwicaptcha:argon2:leases:'.$suffix;
        // The waiters counter must live in the same hash slot as the lease
        // set (one EVAL script touches both keys), so it is hash-tagged with
        // the lease key's tag family.
        $this->waitersKey = '{kiwicaptcha:argon2:leases:'.$suffix.'}:sem:waiters';
    }

    /**
     * Acquire an Argon2id admission slot. Immediate and non-blocking: on
     * saturation (the global or per-scope cap is full) the method returns
     * null right away and the "waiters" counter records the
     * saturation-pressure spike. A rejected request is never queued,
     * polled or later admitted (the counter is a gauge, not a queue).
     *
     * @param string|null $scope the scope string (the challenge's scope) for
     *                           the per-scope budget: the scope's
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
     *                           per-scope budget).
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
        // Per-scope set: {kiwicaptcha:argon2:leases:<ns>}:<sha256(scope)>
        // — hash-tagged with the same family as the waiters counter
        // (Cluster safe). The scope is hashed, never sanitized: a
        // lossy sanitization would collapse distinct legitimate scopes
        // (tenant:a and tenant_a share one per-tenant budget, letting
        // one starve the other) and would leak scope names into the
        // key. The token carries the hashed scope suffix so release()
        // can remove the lease from both sets.
            $scopeSuffix = hash('sha256', $scope);
            $scopeKey = '{'.$this->key.'}:'.$scopeSuffix;
            $token .= '.'.$scopeSuffix;
            $hasScope = true;
        }
        $result = $this->eval(
            self::ACQUIRE_SCRIPT,
            [$this->key, $this->waitersKey, $scopeKey !== '' ? $scopeKey : $this->key],
            [(string) $this->maxConcurrent, (string) $this->leaseMs, $token, (string) $this->maxWaiters, (string) $this->maxPerScope, $hasScope ? '1' : '0'],
        );

        return $result === 1 ? $token : null;
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
