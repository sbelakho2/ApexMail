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
 *   {kiwi:<ns>}:outstanding:source      the per-source live membership: a
 *                                       single ZSET for every source, member
 *                                       `<source-pseudonym>:<nonce>`, score
 *                                       the challenge's absolute expiry. The
 *                                       per-source bound is the lex count of
 *                                       that source's members after pruning
 *                                       expired ones, so the bound is
 *                                       EXPIRY-AWARE: a short-TTL challenge
 *                                       can never shorten the lifetime of
 *                                       the source's other outstanding
 *                                       challenges (the old scalar counter
 *                                       EXPIRE reset the whole counter to
 *                                       the newest challenge's TTL, a
 *                                       per-source hard-cap bypass).
 *   {kiwi:<ns>}:outstanding:global:live deployment-wide live-outstanding
 *                                       membership (a Redis ZSET).
 *   {kiwi:<ns>}:outstanding:nonce:<nonce>  issuance sidecar: pairs the
 *                                       nonce with its original source
 *                                       pseudonym, so a later release can
 *                                       return exactly the source that
 *                                       issued the challenge, and never the
 *                                       releaser's.
 *   {kiwi:<ns>}:cancel:<hex>            per-source cancellation window.
 *
 * The source identity is the hex form of
 * hmac_sha256(canonical-ip-bytes, RiskKeys::event). The raw IP never
 * appears in Redis, and the same canonical key as the
 * challenge binding tag is used (IPv4-mapped-IPv6 normalized), so two
 * textual spellings of one address hit the same source. The HMAC key is
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
 * accumulate issuance refusals. The per-source bound is the same model:
 * the source membership ZSET prunes expired members and counts the live
 * ones per source with ZLEXCOUNT, so heterogeneous challenge TTLs cannot
 * reset the source bound's lifetime and expired challenges stop counting
 * immediately. A client cancellation returns the original source's slot
 * too. The issuance sidecar (`outstanding:nonce:<nonce>`) pairs the
 * nonce with the source pseudonym that issued it. The release is
 * one-shot: the live-membership ZREM is the gate, only then is the
 * sidecar read and the ORIGINAL source's membership released. The
 * releaser's own identity is never used, since the identity would be
 * wrong and the request client-controlled. Only the sidecar's original
 * source is released, and only when the global member actually existed.
 * A duplicate release is a no-op, so nothing can ever be
 * double-released.
 *
 * The `ZREMRANGEBYSCORE` prune is bounded by the ZSET's own size: a
 * member is removed exactly when its score fell below the current time.
 * Both ZSETs are bounded by the global cap plus, transiently, the
 * requests between the prune and their `ZADD`; see the issuance script.
 * The `global:live` key is deliberately named apart from the legacy
 * `global` counter key, so a deployment rolling out this accounting
 * never reads a `WRONGTYPE` on the legacy key type while its string
 * counter is still decaying.
 *
 * Every script accesses ONLY keys supplied as KEYS arguments: no
 * programmatically generated key names, no key names derived from stored
 * data. The source pseudonym read from the sidecar becomes a ZSET
 * MEMBER (the source membership's member encoding `source:nonce`), never
 * a key name, so the scripts stay inside the EVAL contract on sharded /
 * proxied / Redis Cloud topologies as well as standalone and OSS Cluster
 * (all keys share the one {kiwi:<ns>} hash slot).
 *
 * Verification, see {@see solved()}: one-shot, nonce-authoritative
 * release of the solved nonce from the live membership, the original
 * source membership and the sidecar when a challenge verifies
 * successfully. The nonce is the authoritative member identity, so the
 * solve removes exactly the challenge that was solved. The call is
 * idempotent and safe on retries: only the first removal releases
 * anything.
 *
 * Aborted before handoff, see {@see abortedBeforeHandoff()}: when a
 * challenge was admitted but proven never handed out (a
 * mint/metadata/chain-state failure the controller can positively
 * attribute), the original source's slot is returned with the SAME
 * nonce-authoritative model as solve and cancel: the nonce's live
 * membership is removed and only that removal releases the original
 * source membership and drops the sidecar. A crashed issuance therefore
 * does not silently consume the source's stockpile budget or the
 * deployment's live membership. An indeterminate failure (the chain
 * state cannot be read after a thrown issuance transition, the
 * challenge may be the authoritative issued stage-2) must not call
 * this: the slot belongs to the client until proven otherwise.
 *
 * Cancellation, see {@see cancelled()}: the server side of the
 * exhaustion->debt feedback break. A widget that abandons a challenge
 * (its bounded solve search exhausted on a stochastic tail) tells the
 * server. The server removes the nonce from the live membership and
 * returns the original source's outstanding slot, the one that issued
 * the challenge. The canceller's own slot is never released. The
 * abandoned challenge then stops counting against the deployment cap
 * and the source quota while its record stays retained until its TTL.
 * The record's own pending->cancelled transition is the storage layer's,
 * see the CancellableStorageInterface capability.
 *
 * Failure behavior: a Redis error on issuance is never swallowed: the
 * caller (challenge controller) refuses issuance when the counter cannot
 * be consulted (fail closed: no challenge without a checked stockpile
 * bound). The verification-side release is best-effort (a failed release
 * never breaks a valid solve; the memberships decay by their expiry
 * scores — fail-closed, the caps are overcounted, never undercounted).
 */
final class OutstandingChallenges
{
    /**
     * Atomic check + admit + live-membership add + source sidecar:
     *   KEYS[1] = {kiwi:<ns>}:outstanding:source (the per-source
     *             membership ZSET, one declared key for every source —
     *             the source is a MEMBER prefix, never a key name).
     *   KEYS[2] = {kiwi:<ns>}:outstanding:global:live (live-outstanding ZSET).
     *   KEYS[3] = {kiwi:<ns>}:outstanding:nonce:<nonce> (issuance sidecar).
     *   ARGV[1] = per-source cap.
     *   ARGV[2] = global cap (live-outstanding members).
     *   ARGV[3] = TTL in seconds (challenge lifetime + ttl margin) for the
     *             sidecar only. The per-source bound has NO scalar expiry
     *             to reset: its members expire by their absolute scores.
     *   ARGV[4] = the challenge's absolute expiry in epoch seconds. This
     *             is the ZSET score, so a member dies exactly when its
     *             challenge expires and is never refreshed.
     *   ARGV[5] = the minted challenge nonce, which is the global ZSET
     *             member and the `<source>:<nonce>` source member suffix.
     *   ARGV[6] = the issuing source's pseudonym (an HMAC and never a raw
     *             IP). It is the source member prefix and is stored in the
     *             sidecar so a later release returns exactly this
     *             source's slot.
     * Prunes expired members with `ZREMRANGEBYSCORE` -inf now, bounded by
     * the ZSETs' sizes. Refuses (0 = source cap, -1 = global cap) before
     * any admission write. The per-source count is the source's live
     * membership (ZLEXCOUNT of the `[<source>:` lex range): a challenge
     * issued with a short TTL expires from the source membership on its
     * own schedule and can never shorten the lifetime of the source's
     * other outstanding challenges (the scalar EXPIRE of the previous
     * design reset the whole per-source counter to the newest TTL, a hard
     * bound that the configuration's heterogeneous sitekey TTLs could
     * bypass). Then `ZADD`s both memberships and `SET`s the sidecar. A
     * challenge is only returned to the client when the script admitted
     * it, so the bounds can never silently exceed the caps through
     * concurrency.
     */
    private const ISSUE_SCRIPT = <<<'LUA'
-- Outstanding challenge issuance: atomic per-source live ZLEXCOUNT cap check
-- + global live cap check + memberships ZADD + source sidecar. The per-source
-- bound is the source's LIVE membership (members expire by their absolute
-- scores), so no scalar TTL can ever be reset by a heterogeneous challenge.
local t = redis.call('TIME')
local now = tonumber(t[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local src = redis.call('ZLEXCOUNT', KEYS[1], '[' .. ARGV[6] .. ':', '[' .. ARGV[6] .. ':\xff')
if tonumber(src) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then return -1 end
redis.call('ZADD', KEYS[1], tonumber(ARGV[4]), ARGV[6] .. ':' .. ARGV[5])
redis.call('ZADD', KEYS[2], tonumber(ARGV[4]), ARGV[5])
redis.call('SET', KEYS[3], ARGV[6], 'EX', tonumber(ARGV[3]))
return 1
LUA;

    /**
     * The single nonce-authoritative release, shared by solve, client
     * cancellation and proven-not-handed-off issuance abort: the
     * live-membership ZREM is the ONE-SHOT gate; only its removal reads
     * the issuance sidecar, releases the ORIGINAL source's membership
     * (the `<source>:<nonce>` member — the source pseudonym is a member
     * prefix, never a key name) and deletes the sidecar. The caller's
     * identity plays no role (a challenge issued through source A and
     * released from source B must release A's slot, never B's — IP
     * binding may be disabled). Duplicate releases are harmless: only
     * the removal of the nonce from the live membership releases
     * anything, and a member that expired away removes nothing. Every
     * accessed key is a declared KEYS argument — no dynamically
     * discovered key names, so the script honors the EVAL contract on
     * standalone, OSS Cluster and stricter sharded/proxied topologies.
     *   KEYS[1] = the global live-outstanding ZSET.
     *   KEYS[2] = the nonce's issuance sidecar.
     *   KEYS[3] = the per-source membership ZSET.
     *   ARGV[1] = the released challenge nonce.
     */
    private const RELEASE_SCRIPT = <<<'LUA'
-- Outstanding challenge release (solve / cancel / aborted-before-handoff):
-- one-shot ZREM-gated release of the ORIGINAL source's membership + sidecar
-- DEL. All keys are declared; the sidecar's source is a ZSET member prefix.
local removed = redis.call('ZREM', KEYS[1], ARGV[1])
if removed == 1 then
  local source = redis.call('GET', KEYS[2])
  if source and source ~= '' then
    redis.call('ZREM', KEYS[3], source .. ':' .. ARGV[1])
    redis.call('DEL', KEYS[2])
  end
end
return removed
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
     *                                               sidecar beyond token
     *                                               validity
     *                                               (risk.redis.ttl_margin_secs).
     *                                               The memberships expire by
     *                                               their absolute expiry
     *                                               scores, never by this
     *                                               margin.
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
     * The per-source pseudonym for a client IP: the raw IP never appears
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
     * Admit one issued challenge. The script atomically checks both caps
     * against the LIVE memberships (pruned of expired members, so a
     * heterogeneous challenge TTL can never reset the source bound's
     * lifetime), then adds the minted nonce to the per-source and global
     * memberships (scored at its absolute expiry) and writes the issuance
     * sidecar (the nonce -> original source pseudonym). The challenge
     * must already be minted: the ZSET members are the nonce and their
     * scores the expiry, which exist only once the record is minted. The
     * admission runs before handoff, so a refused admission never hands
     * out (the caller discards the minted record). The sidecar stores
     * only the HMAC source pseudonym, never a raw IP, and lets the
     * release paths return exactly the source that issued the challenge.
     *
     * @param string $clientIp        the canonical client IP.
     * @param string $nonce           the minted challenge's nonce (the
     *                                live-membership member).
     * @param int    $expiresAtSecs   the challenge's absolute expiry, epoch
     *                                seconds (the membership score, so the
     *                                member dies exactly when the challenge
     *                                expires).
     * @param int    $challengeTtlSecs the challenge lifetime, seconds (the
     *                                 sidecar EXPIRE basis).
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
        $sourceZset = $this->keyPrefix.'source';
        $global = $this->keyPrefix.'global:live';
        $sidecar = $this->keyPrefix.'nonce:'.$nonce;

        return (int) $this->eval(self::ISSUE_SCRIPT, [$sourceZset, $global, $sidecar], [
            (string) $this->maxPerSource,
            (string) $this->maxGlobal,
            (string) max(1, $ttl),
            (string) $expiresAtSecs,
            $nonce,
            substr($source, \strlen($this->keyPrefix)),
        ]);
    }

    /**
     * One-shot, nonce-authoritative release: removes the solved nonce
     * from the live membership, and only when the removal actually
     * happened, reads the nonce's issuance sidecar and releases the
     * ORIGINAL source's membership (floored by its own expiry scores),
     * then drops the sidecar. The caller's IP is never used; a duplicate
     * solve (ZREM == 0) releases nothing. Never throws: a failed release
     * must never break a valid solve (the memberships decay by their
     * expiries otherwise — fail-closed, the caps are overcounted, never
     * undercounted).
     */
    public function solved(string $nonce): void
    {
        try {
            $this->eval(self::RELEASE_SCRIPT, [
                $this->keyPrefix.'global:live',
                $this->keyPrefix.'nonce:'.$nonce,
                $this->keyPrefix.'source',
            ], [$nonce]);
        } catch (\Throwable) {
            // Best-effort: an unavailable membership must never fail a
            // valid solve.
        }
    }

    /**
     * Nonce-authoritative release when an admitted challenge was proven
     * never handed out (the controller's proven-not-handed-out failure
     * paths): the exact same one-shot model as solve and cancellation —
     * the nonce's live membership is removed and only that removal
     * releases the original source's membership and drops the sidecar.
     * The source slot is returned so a crashed issuance does not
     * silently consume the source's stockpile budget. The nonce leaves
     * the deployment-wide live membership so an abandoned challenge
     * never counts against the global cap, and its issuance sidecar is
     * dropped. Never throws: a failed rollback must never change the
     * issuance response. The caller must not call this for an
     * indeterminate failure (the chain state cannot be read after a
     * thrown issuance transition — the challenge may be the
     * authoritative issued stage-2). Without a nonce there is no
     * membership to gate on, so nothing is released.
     */
    public function abortedBeforeHandoff(?string $nonce = null): void
    {
        if ($nonce === null || $nonce === '') {
            return;
        }
        try {
            $this->eval(self::RELEASE_SCRIPT, [
                $this->keyPrefix.'global:live',
                $this->keyPrefix.'nonce:'.$nonce,
                $this->keyPrefix.'source',
            ], [$nonce]);
        } catch (\Throwable) {
            // Best-effort: an unavailable membership must never change
            // the response; the memberships decay by their expiry scores
            // otherwise.
        }
    }

    /**
     * One-shot live-membership removal + original-source slot release for
     * a client-cancelled challenge. Called by the cancellation endpoint
     * after the record's atomic pending->cancelled transition
     * (CancellableStorageInterface). The ZREM gate makes it idempotent:
     * cancelling a nonce with no live member (never issued, expired away,
     * or already removed by a solve/abort/cancellation) is a no-op. The
     * original source membership (from the issuance sidecar, never the
     * canceller's IP) is released exactly once per issued challenge.
     */
    public function cancelled(string $nonce): void
    {
        try {
            $this->eval(self::RELEASE_SCRIPT, [
                $this->keyPrefix.'global:live',
                $this->keyPrefix.'nonce:'.$nonce,
                $this->keyPrefix.'source',
            ], [$nonce]);
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
