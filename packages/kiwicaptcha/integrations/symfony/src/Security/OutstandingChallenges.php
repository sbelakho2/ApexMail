<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\Issuer;
use KiwiCaptcha\Risk\RiskKeys;

/**
 * Anti-stockpiling: bounded outstanding UNSOLVED challenges per source and
 * deployment-wide (the audit #26 counter design).
 *
 * Keys (one hash-tag family {kiwi:<ns>} — Cluster safe):
 *   {kiwi:<ns>}:outstanding:<hex>          per-source counter
 *   {kiwi:<ns>}:outstanding:global         deployment-wide counter
 *
 * The source identity is hex(hmac_sha256(canonical-ip-bytes, RiskKeys::event)):
 * the raw IP NEVER appears in Redis, and the same canonical key as the
 * challenge binding tag is used (IPv4-mapped-IPv6 normalized), so two textual
 * spellings of one address hit the same counter. The HMAC key is the risk
 * package's purpose-separated 'event' key (derived from the risk master
 * secret by RiskKeys::fromMaster) — shared with the risk engine's own
 * event-id pseudonyms, never a raw identifier.
 *
 * Issuance ({@see issue()}): ONE atomic Lua script — GET both counters,
 * refuse (0 = source cap, -1 = global cap) BEFORE anything is written, then
 * INCR both and EXPIRE both with (challenge lifetime + ttl_margin_secs). A
 * challenge is only returned to the client when the script admitted it, so
 * the counters can never silently exceed the caps through concurrency.
 *
 * Verification ({@see solved()}): best-effort DECR of the PER-SOURCE counter
 * (floored at 0) when a challenge verifies successfully. The GLOBAL counter
 * is never decremented: it is deployment-wide pressure that decays only by
 * EXPIRE (identity-neutral, matching the risk engine's global-pressure
 * semantics).
 *
 * Failure behavior: a Redis error on issuance is NOT swallowed — the caller
 * (challenge controller) refuses issuance when the counter cannot be
 * consulted (fail closed: no challenge without a checked stockpile bound).
 * The verification-side decrement IS best-effort (a failed DECR never breaks
 * a valid solve).
 */
final class OutstandingChallenges
{
    /**
     * Atomic check + increment + expiry:
     *   KEYS[1] = {kiwi:<ns>}:outstanding:<hex>   (per-source counter)
     *   KEYS[2] = {kiwi:<ns>}:outstanding:global  (global counter)
     *   ARGV[1] = per-source cap
     *   ARGV[2] = global cap
     *   ARGV[3] = TTL in seconds (challenge lifetime + ttl margin)
     * Returns 1 when admitted (both counters incremented + expired),
     * 0 when the per-source cap is reached, -1 when the global cap is
     * reached (nothing written on refusal).
     */
    private const ISSUE_SCRIPT = <<<'LUA'
-- Outstanding challenge issuance: atomic cap check + INCR both + EXPIRE
local src = tonumber(redis.call('GET', KEYS[1]) or '0')
local glb = tonumber(redis.call('GET', KEYS[2]) or '0')
if src >= tonumber(ARGV[1]) then return 0 end
if glb >= tonumber(ARGV[2]) then return -1 end
redis.call('INCR', KEYS[1])
redis.call('INCR', KEYS[2])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
return 1
LUA;

    /**
     * Best-effort per-source decrement after a VALID verification:
     *   KEYS[1] = the per-source counter
     * Floored at 0 (a DECR can never drive the counter negative — a
     * verification after the counter expired must not fabricate a negative
     * outstanding count that later admits extra issuances).
     */
    private const SOLVED_SCRIPT = <<<'LUA'
-- Outstanding challenge solve: best-effort DECR floored at 0
local v = tonumber(redis.call('GET', KEYS[1]) or '0')
if v > 0 then redis.call('DECR', KEYS[1]) end
return v - 1
LUA;

    /**
     * @param \Redis|\Predis\Client $redis           Redis client shared with
     *                                               the risk state store
     * @param string                $keyPrefix       full key prefix including
     *                                               the hash tag, e.g.
     *                                               "{kiwi:prod}:outstanding:"
     * @param RiskKeys              $keys            purpose-separated risk
     *                                               identity keys; the 'event'
     *                                               key HMACs the canonical IP
     * @param int                   $maxPerSource    per-source cap
     *                                               (risk.max_outstanding_challenges)
     * @param int                   $maxGlobal       deployment-wide cap
     *                                               (risk.max_outstanding_challenges_global)
     * @param int                   $ttlMarginSecs   extra retention on the
     *                                               counters beyond token
     *                                               validity (risk.redis.ttl_margin_secs)
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $redis,
        private readonly string $keyPrefix,
        private readonly RiskKeys $keys,
        private readonly int $maxPerSource,
        private readonly int $maxGlobal,
        private readonly int $ttlMarginSecs = 0,
    ) {
    }

    /**
     * The per-source counter key for a client IP: the raw IP never appears
     * in Redis — only hex(hmac_sha256(canonical-ip-bytes, keys->event)).
     * An unparseable IP (or an empty one) is bucketed with the other
     * unidentifiable sources under a constant tag (conservative shared
     * budget, mirroring the issuance rate limiter).
     */
    public function sourceKey(string $clientIp): string
    {
        try {
            $identity = Issuer::canonicalIpFamily($clientIp);
        } catch (\InvalidArgumentException) {
            $identity = 'unknown';
        }

        return $this->keyPrefix.hash_hmac('sha256', $identity, $this->keys->event);
    }

    /**
     * Admit one issued challenge: atomic check of BOTH caps, then INCR both
     * counters and EXPIRE both with (challenge lifetime + ttl margin).
     *
     * @return int 1 = admitted, 0 = per-source cap reached, -1 = global cap
     *              reached (nothing written on refusal)
     *
     * @throws \Throwable when Redis fails (fail closed — the caller refuses
     *                    issuance rather than minting an unchecked challenge)
     */
    public function issue(string $clientIp, int $challengeTtlSecs): int
    {
        $ttl = $challengeTtlSecs + $this->ttlMarginSecs;
        $source = $this->sourceKey($clientIp);
        $global = $this->keyPrefix.'global';

        return (int) $this->eval(self::ISSUE_SCRIPT, [$source, $global], [
            (string) $this->maxPerSource,
            (string) $this->maxGlobal,
            (string) max(1, $ttl),
        ]);
    }

    /**
     * Best-effort per-source decrement after a VALID verification. Never
     * throws: a failed decrement must never break a valid solve (the counter
     * only decays by its EXPIRE otherwise).
     */
    public function solved(string $clientIp): void
    {
        try {
            $this->eval(self::SOLVED_SCRIPT, [$this->sourceKey($clientIp)], []);
        } catch (\Throwable) {
            // Best-effort: an unavailable counter must never fail a valid
            // solve.
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
        if ($this->redis instanceof \Redis) {
            // phpredis signature: eval($script, $args, $numKeys)
            return $this->redis->eval($script, [...$keys, ...$args], \count($keys));
        }

        // Predis signature: eval($script, $numkeys, ...$keysAndArgs)
        return $this->redis->eval($script, \count($keys), ...$keys, ...$args);
    }
}
