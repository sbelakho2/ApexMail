<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\Issuer;
use KiwiCaptcha\Risk\RiskKeys;

/**
 * Anti-stockpiling: bounded outstanding unsolved challenges per source and
 * deployment-wide.
 *
 * Keys (one hash-tag family {kiwi:<ns>}, Cluster safe):
 *   {kiwi:<ns>}:outstanding:<hex>          per-source counter.
 *   {kiwi:<ns>}:outstanding:global:live    deployment-wide live-outstanding
 *                                          membership (a Redis ZSET).
 *   {kiwi:<ns>}:cancel:<hex>               per-source cancellation window.
 *
 * The source identity is the hex form of
 * hmac_sha256(canonical-ip-bytes, RiskKeys::event). The raw IP never
 * appears in Redis, and the same canonical key as the
 * challenge binding tag is used (IPv4-mapped-IPv6 normalized), so two
 * textual spellings of one address hit the same counter. The HMAC key is
 * the risk package's purpose-separated 'event' key (derived from the risk
 * master secret by RiskKeys::fromMaster), shared with the risk engine's
 * own event-id pseudonyms, never a raw identifier.
 *
 * The global accounting is an expiry-aware membership, not a cumulative
 * counter: {@see issue()} runs one atomic Lua that prunes expired members
 * with `ZREMRANGEBYSCORE` -inf now and refuses when ZCARD >= the global
 * cap. It then `ZADD`s the minted challenge's nonce scored at its
 * absolute expiry (expires_at, never a refreshed now + TTL). The
 * membership is therefore genuinely "currently live unresolved
 * challenges". A solve via {@see solved()}, a proven-not-handed-off
 * issuance failure via {@see abortedBeforeHandoff()} and a client
 * cancellation via {@see cancelled()} all ZREM the nonce. A member can
 * never outlive its challenge: the score expires it even if every removal
 * path fails. The global cap is a real bound on live challenges, not a
 * cumulative high-water mark, so sustained traffic can no longer
 * accumulate issuance refusals. The per-source counter keeps its existing
 * INCR/DECR semantics (solves and proven-not-handed-off rollbacks
 * decrement it best-effort, floored at 0).
 *
 * The `ZREMRANGEBYSCORE` prune is bounded by the ZSET's own size: a
 * member is removed exactly when its score fell below the current time.
 * The ZSET is bounded by the global cap plus, transiently, the requests
 * between the prune and their `ZADD`; see the issuance script. The
 * `global:live` key is deliberately named apart from the legacy
 * `global` counter key, so a deployment rolling out this accounting
 * never reads a `WRONGTYPE` on the legacy key type while its string
 * counter is still decaying.
 *
 * Verification, see {@see solved()}: best-effort DECR of the per-source
 * counter (floored at 0) plus a ZREM of the solved nonce from the global
 * live membership when a challenge verifies successfully. The nonce is
 * the authoritative member identity, so the solve removes exactly the
 * challenge that was solved.
 *
 * Aborted before handoff, see {@see abortedBeforeHandoff()}: when a
 * challenge was admitted but proven never handed out (a
 * mint/metadata/chain-state failure the controller can positively
 * attribute), the per-source slot is returned best-effort (floored at 0).
 * The nonce is removed from the global live membership. A crashed
 * issuance therefore does not silently consume the source's stockpile
 * budget or the deployment's live membership. An indeterminate failure
 * (the chain state cannot be read after a thrown issuance transition,
 * the challenge may be the authoritative issued stage-2) must not call
 * this: the slot belongs to the client until proven otherwise.
 *
 * Cancellation, see {@see cancelled()}: the server side of the
 * exhaustion->debt feedback break. A widget that abandons a challenge
 * (its bounded solve search exhausted on a stochastic tail) tells the
 * server, which removes the nonce from the live membership. The
 * abandoned challenge then stops counting against the deployment cap
 * while its record stays retained until its TTL. The record's own
 * pending->cancelled transition is the storage layer's, see the
 * CancellableStorageInterface capability.
 *
 * Failure behavior: a Redis error on issuance is never swallowed: the
 * caller (challenge controller) refuses issuance when the counter cannot
 * be consulted (fail closed: no challenge without a checked stockpile
 * bound). The verification-side decrement is best-effort (a failed DECR
 * never breaks a valid solve).
 */
final class OutstandingChallenges
{
    /**
     * Atomic check + increment + live-membership add:
     *   KEYS[1] = {kiwi:<ns>}:outstanding:<hex>   (per-source counter).
     *   KEYS[2] = {kiwi:<ns>}:outstanding:global:live (live-outstanding ZSET).
     *   ARGV[1] = per-source cap.
     *   ARGV[2] = global cap (live-outstanding members).
     *   ARGV[3] = TTL in seconds (challenge lifetime + ttl margin) for the
     *             per-source counter.
     *   ARGV[4] = the challenge's absolute expiry (epoch seconds) — the
     *             ZSET score, so a member dies exactly when its challenge
     *             expires and is never refreshed.
     *   ARGV[5] = the minted challenge nonce — the ZSET member.
     * Prunes expired members with `ZREMRANGEBYSCORE` -inf now (bounded
     * by the ZSET's size), refuses (0 = source cap, -1 = global cap)
     * before any admission write, then INCR + EXPIRE the per-source
     * counter and `ZADD` the nonce at its absolute expiry. A challenge is
     * only returned to the client when the script admitted it, so the
     * counters can never silently exceed the caps through concurrency.
     */
    private const ISSUE_SCRIPT = <<<'LUA'
-- Outstanding challenge issuance: atomic cap check + INCR + EXPIRE + live-membership ZADD
local src = tonumber(redis.call('GET', KEYS[1]) or '0')
local t = redis.call('TIME')
local now = tonumber(t[1])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if src >= tonumber(ARGV[1]) then return 0 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then return -1 end
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
redis.call('ZADD', KEYS[2], tonumber(ARGV[4]), ARGV[5])
return 1
LUA;

    /**
     * Best-effort per-source decrement + live-membership removal after a
     * valid verification.
     * KEYS[1] = the per-source counter.
     * KEYS[2] = the global live-outstanding ZSET.
     * ARGV[1] = the solved challenge nonce ('' = none; the caller without
     *           the nonce still decrements the per-source counter).
     * Floored at 0: a DECR can never drive the counter negative, and a
     * verification after the counter expired must not fabricate a negative
     * outstanding count that later admits extra issuances. The ZREM is
     * idempotent (a member that expired away removes nothing).
     */
    private const SOLVED_SCRIPT = <<<'LUA'
-- Outstanding challenge solve: best-effort DECR floored at 0 + live-membership ZREM
local v = tonumber(redis.call('GET', KEYS[1]) or '0')
if v > 0 then redis.call('DECR', KEYS[1]) end
if ARGV[1] ~= '' then redis.call('ZREM', KEYS[2], ARGV[1]) end
return v - 1
LUA;

    /**
     * Best-effort per-source decrement + live-membership removal when an
     * admitted challenge was proven not handed out (the controller's
     * proven-not-handed-out failure paths — mint/metadata/chain-state
     * failures).
     * KEYS[1] = the per-source counter.
     * KEYS[2] = the global live-outstanding ZSET.
     * ARGV[1] = the abandoned challenge nonce ('' = none).
     * Floored at 0: a DECR can never drive the counter negative. The ZREM
     * is idempotent. Best-effort like solved(): a failed rollback never
     * changes the response; the membership decays by its expiry scores and
     * the per-source counter by its EXPIRE otherwise.
     */
    private const ABORTED_SCRIPT = <<<'LUA'
-- Outstanding challenge aborted before handoff: best-effort DECR floored at 0 + live-membership ZREM
local v = tonumber(redis.call('GET', KEYS[1]) or '0')
if v > 0 then redis.call('DECR', KEYS[1]) end
if ARGV[1] ~= '' then redis.call('ZREM', KEYS[2], ARGV[1]) end
return 1
LUA;

    /**
     * Best-effort live-membership removal for a client-cancelled
     * challenge (the cancellation endpoint's ZREM half; the record's
     * pending->cancelled transition is the storage layer's).
     * KEYS[1] = the global live-outstanding ZSET.
     * ARGV[1] = the cancelled challenge nonce.
     * The ZREM is idempotent; a failure leaves the member to expire by its
     * score (fail-closed: the cap is overcounted, never undercounted).
     */
    private const CANCELLED_SCRIPT = <<<'LUA'
-- Outstanding challenge cancelled: live-membership ZREM (best-effort)
redis.call('ZREM', KEYS[1], ARGV[1])
return 1
LUA;

    /**
     * Atomic per-source cancellation window (a sliding window in the
     * issuance-rate-limiter style): bounds how many cancellation requests
     * one source may send, so the endpoint's per-IP cost is bounded.
     *   KEYS[1] = {kiwi:<ns>}:cancel:<hex>  (per-source window ZSET).
     *   ARGV[1] = per-IP cap.
     *   ARGV[2] = window in ms.
     *   ARGV[3] = unique request id (ZSET member).
     * Returns 1 when the window has room, 0 when the cap is exhausted
     * (after pruning expired hits). A Redis failure propagates: the caller
     * fails closed.
     */
    private const CANCEL_ADMISSION_SCRIPT = <<<'LUA'
-- Outstanding challenge cancellation admission: per-source sliding window
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
local cutoff = now - tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) + 1000)
return 1
LUA;

    /** The cancellation endpoint's per-source sliding window, ms. */
    public const CANCELLATION_WINDOW_MS = 60_000;

    /** The cancellation endpoint's per-source cap per window. */
    public const CANCELLATION_PER_IP_CAP = 120;

    /**
     * @param \Redis|\Predis\Client $redis           Redis client shared with
     *                                               the risk state store.
     * @param string                $keyPrefix       full key prefix including
     *                                               the hash tag, e.g.
     *                                               "{kiwi:prod}:outstanding:".
     * @param RiskKeys              $keys            purpose-separated risk
     *                                               identity keys; the 'event'
     *                                               key HMACs the canonical IP.
     * @param int                   $maxPerSource    per-source cap
     *                                               (risk.max_outstanding_challenges).
     * @param int                   $maxGlobal       deployment-wide cap on live
     *                                               outstanding challenges
     *                                               (risk.max_outstanding_challenges_global).
     * @param int                   $ttlMarginSecs   extra retention on the
     *                                               per-source counter beyond
     *                                               token validity
     *                                               (risk.redis.ttl_margin_secs).
     *                                               The ZSET members expire by
     *                                               their absolute expiry
     *                                               scores, never by this margin
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
     * in Redis, only the hex form of
     * hmac_sha256(canonical-ip-bytes, keys->event).
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
     * Admit one issued challenge: atomic check of both caps against the
     * live membership, then INCR + EXPIRE the per-source counter and
     * `ZADD` the minted nonce at its absolute expiry. The challenge must
     * already be minted: the ZSET member is the nonce and its score the
     * expiry, which exist only once the record is minted. The admission
     * runs before handoff, so a refused admission never hands out (the
     * caller discards the minted record).
     *
     * @param string $clientIp        the canonical client IP.
     * @param string $nonce           the minted challenge's nonce (the
     *                                live-membership member).
     * @param int    $expiresAtSecs   the challenge's absolute expiry, epoch
     *                                seconds (the membership score, so the
     *                                member dies exactly when the challenge
     *                                expires).
     * @param int    $challengeTtlSecs the challenge lifetime, seconds (the
     *                                per-source counter EXPIRE basis).
     *
     * @return int 1 = admitted, 0 = per-source cap reached, -1 = global cap
     *              reached (no admission write on refusal; expired members
     *              are pruned either way).
     *
     * @throws \Throwable when Redis fails (fail closed, so the caller
     *                    refuses issuance rather than minting an unchecked
     *                    challenge)
     */
    public function issue(string $clientIp, string $nonce, int $expiresAtSecs, int $challengeTtlSecs): int
    {
        $ttl = $challengeTtlSecs + $this->ttlMarginSecs;
        $source = $this->sourceKey($clientIp);
        $global = $this->keyPrefix.'global:live';

        return (int) $this->eval(self::ISSUE_SCRIPT, [$source, $global], [
            (string) $this->maxPerSource,
            (string) $this->maxGlobal,
            (string) max(1, $ttl),
            (string) $expiresAtSecs,
            $nonce,
        ]);
    }

    /**
     * Best-effort per-source decrement + live-membership removal after a
     * valid verification. The solved nonce removes exactly the solved
     * challenge from the global membership. Never throws: a failed
     * decrement must never break a valid solve (the counter only decays by
     * its EXPIRE and the membership by its expiry scores otherwise).
     */
    public function solved(string $clientIp, ?string $nonce = null): void
    {
        try {
            $this->eval(self::SOLVED_SCRIPT, [$this->sourceKey($clientIp), $this->keyPrefix.'global:live'], [$nonce ?? '']);
        } catch (\Throwable) {
            // Best-effort: an unavailable counter must never fail a valid
            // solve.
        }
    }

    /**
     * Best-effort per-source decrement + live-membership removal when an
     * admitted challenge was proven never handed out (the controller's
     * proven-not-handed-out failure paths). The source slot is returned
     * so a crashed issuance does not silently consume the source's
     * stockpile budget. The nonce leaves the deployment-wide live
     * membership so an abandoned challenge never counts against the
     * global cap. Never throws: a failed rollback must never change the
     * issuance response. The caller must not call this for an
     * indeterminate failure (the chain state cannot be read after a
     * thrown issuance transition — the challenge may be the authoritative
     * issued stage-2).
     */
    public function abortedBeforeHandoff(string $clientIp, ?string $nonce = null): void
    {
        try {
            $this->eval(self::ABORTED_SCRIPT, [$this->sourceKey($clientIp), $this->keyPrefix.'global:live'], [$nonce ?? '']);
        } catch (\Throwable) {
            // Best-effort: an unavailable counter must never change the
            // response; the membership decays by its expiry scores and the
            // per-source counter by its EXPIRE otherwise.
        }
    }

    /**
     * Best-effort live-membership removal for a client-cancelled
     * challenge. Called by the cancellation endpoint after the record's
     * atomic pending->cancelled transition (CancellableStorageInterface);
     * idempotent — cancelling a nonce with no live member (never issued,
     * expired away, or already removed by a solve/abort) is a no-op.
     */
    public function cancelled(string $nonce): void
    {
        try {
            $this->eval(self::CANCELLED_SCRIPT, [$this->keyPrefix.'global:live'], [$nonce]);
        } catch (\Throwable) {
            // Best-effort: a failed removal never changes the cancellation
            // response; the member expires by its score (fail-closed: the
            // cap is overcounted, never undercounted).
        }
    }

    /**
     * Whether the source may send another cancellation request: the
     * endpoint's bounded per-IP limiter (a sliding window, pruned and
     * checked atomically). Throws on a Redis failure (fail closed — the
     * endpoint refuses rather than letting an unbounded cancellation
     * stream through).
     */
    public function cancellationAdmission(string $clientIp): bool
    {
        $source = $this->sourceKey($clientIp);
        $window = $this->keyPrefix.'cancel:'.substr($source, \strlen($this->keyPrefix));

        return (int) $this->eval(self::CANCEL_ADMISSION_SCRIPT, [$window], [
            (string) self::CANCELLATION_PER_IP_CAP,
            (string) self::CANCELLATION_WINDOW_MS,
            bin2hex(random_bytes(16)),
        ]) === 1;
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
