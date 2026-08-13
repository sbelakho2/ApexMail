<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\VerificationAdmissionGate;

/**
 * Redis-backed Argon2id admission gate — the audit's TOKENIZED-LEASE design.
 *
 * Caps concurrent Argon2id verifications ACROSS all PHP-FPM workers sharing
 * the Redis instance. Implements the core's
 * {@see \KiwiCaptcha\VerificationAdmissionGate}: acquire() returns an opaque
 * lease token, release() removes exactly that token. Stale releases cannot
 * remove a newer lease: a lease is a unique member of a sorted set, so
 * releasing an expired/double-released token is a no-op (ZREM of an absent
 * member) and can never touch a different token's slot.
 *
 * Each lease is a sorted-set member scored at its expiry (now + LEASE_MS).
 * The acquire script prunes expired leases first (ZREMRANGEBYSCORE up to
 * `now` — a lease whose score is in the past is dead), then admits when the
 * live count is below the cap. A worker that crashes while holding a lease
 * never releases it, but its lease expires after LEASE_MS and is reaped by
 * the next acquire — no watchdog counter to drift, no DECR race.
 *
 * Key: `kiwicaptcha:argon2:leases:<namespace>` — one lease set per
 * deployment; the namespace is sanitized to [A-Za-z0-9_.-] (defaults to
 * 'default' when empty).
 *
 * A `maxConcurrent` <= 0 disables the cap: acquire() returns the sentinel
 * token 'disabled' and release() no-ops — the verifier's lease lifecycle
 * stays uniform.
 */
final class RedisAdmissionSemaphore implements VerificationAdmissionGate
{
    /** Default lease lifetime in ms; expired leases are reaped by the next acquire. */
    private const DEFAULT_LEASE_MS = 45_000;

    /**
     * Atomic acquire (exact audit semantics):
     *   KEYS[1]  = lease set key
     *   ARGV[1]  = max concurrent leases (cap)
     *   ARGV[2]  = lease lifetime in ms (LEASE_MS)
     *   ARGV[3]  = unique lease token
     * Returns 1 when the lease was granted, 0 when the cap is saturated
     * (nothing is written on rejection).
     */
    private const ACQUIRE_SCRIPT = <<<'LUA'
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[3])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2])*2)
return 1
LUA;

    /**
     * Atomic release (exact audit semantics): removes exactly the lease
     * token. ZREM of an absent member is a no-op, so stale releases cannot
     * remove a newer lease.
     *
     * KEYS[1] = lease set key
     * ARGV[1] = lease token to release
     */
    private const RELEASE_SCRIPT = <<<'LUA'
return redis.call('ZREM', KEYS[1], ARGV[1])
LUA;

    /**
     * Atomic-live usage: ONE script — TIME -> now_ms ->
     * ZREMRANGEBYSCORE '-inf' now -> ZCARD. Mirrors the acquire path's
     * pruning, so the returned count is the LIVE lease count (expired
     * leases are reaped exactly as the next acquire would reap them —
     * ZCARD alone would overcount while leases sit un-reaped between
     * acquires).
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

    /**
     * @param \Redis|\Predis\Client $client       Redis client (phpredis or
     *                                            Predis — the same clients
     *                                            RedisStorage accepts; the
     *                                            bundle itself has no hard
     *                                            dependency on either)
     * @param int                   $maxConcurrent cap; <= 0 disables the cap
     * @param string                $namespace     per-deployment discriminator
     *                                             (sanitized to
     *                                             [A-Za-z0-9_.-])
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly int $maxConcurrent,
        string $namespace = 'default',
        private readonly int $leaseMs = self::DEFAULT_LEASE_MS,
    ) {
        if ($leaseMs < 1_000) {
            throw new \InvalidArgumentException('leaseMs must be >= 1000');
        }
        $suffix = preg_replace('/[^A-Za-z0-9_.-]/', '_', $namespace) ?: 'default';
        $this->key = 'kiwicaptcha:argon2:leases:'.$suffix;
    }

    public function acquire(): ?string
    {
        if ($this->maxConcurrent <= 0) {
            return 'disabled';
        }
        $token = bin2hex(random_bytes(16));
        $result = $this->eval(self::ACQUIRE_SCRIPT, [$this->key], [(string) $this->maxConcurrent, (string) $this->leaseMs, $token]);

        return $result === 1 ? $token : null;
    }

    public function release(string $lease): void
    {
        if ($lease === 'disabled') {
            return;
        }
        $this->eval(self::RELEASE_SCRIPT, [$this->key], [$lease]);
    }

    /** The configured concurrency cap (0 = disabled). */
    public function capacity(): int
    {
        return $this->maxConcurrent;
    }

    /**
     * Live number of held leases (atomic TIME + prune + ZCARD in ONE Lua
     * script, so the count is LIVE — expired leases are reaped exactly as
     * the next acquire would reap them), or 0 when the cap is disabled or
     * the backend is unreachable. Read-side telemetry for the
     * resource-pressure provider — never breaks the caller.
     */
    public function usage(): int
    {
        if ($this->maxConcurrent <= 0) {
            return 0;
        }
        try {
            return (int) $this->eval(self::USAGE_SCRIPT, [$this->key], []);
        } catch (\Throwable) {
            return 0;
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
