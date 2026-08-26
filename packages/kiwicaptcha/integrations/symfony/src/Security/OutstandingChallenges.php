<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\Issuer;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Storage\ReplicaWaitException;

/**
 * Anti-stockpiling: bounded outstanding unsolved challenges per source and
 * deployment-wide.
 *
 * Keys (one hash-tag family {kiwi:<ns>}, Cluster safe):
 *   {kiwi:<ns>}:outstanding:<hex>       the per-source LIVE membership: a
 *                                       ZSET per source, member = the
 *                                       challenge nonce, score = the
 *                                       challenge's Redis-clock deadline
 *                                       (Redis TIME + the RELATIVE
 *                                       challenge lifetime). The
 *                                       per-source bound is the source
 *                                       ZSET's ZCARD after pruning expired
 *                                       members by score — a WELL-DEFINED
 *                                       score-range primitive: a
 *                                       short-TTL challenge can never
 *                                       shorten the lifetime of the
 *                                       source's other outstanding
 *                                       challenges, and each member
 *                                       expires on its own schedule.
 *                                       The key itself carries a Redis
 *                                       key TTL (EXPIREAT = latest member
 *                                       deadline + the cleanup margin), so
 *                                       an abandoned source's key can
 *                                       never accumulate in Redis: the
 *                                       stale-key retention is bounded by
 *                                       the longest live member plus the
 *                                       margin, and the keyed source
 *                                       pseudonym disappears with the
 *                                       challenge lifecycle.
 *   {kiwi:<ns>}:outstanding:global:live deployment-wide live-outstanding
 *                                       membership (a Redis ZSET, the same
 *                                       Redis-clock deadlines, the same
 *                                       key-level cleanup TTL).
 *   {kiwi:<ns>}:outstanding:nonce:<nonce>  issuance sidecar: pairs the
 *                                       nonce with its original source
 *                                       pseudonym (the per-source ZSET's
 *                                       hex key suffix), so a later
 *                                       release can return exactly the
 *                                       source that issued the challenge,
 *                                       and never the releaser's.
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
 * Clock domain: the ENTIRE outstanding accounting lives in the Redis
 * clock domain. {@see issue()} receives the RELATIVE challenge lifetime,
 * never a PHP-clock absolute expiry; the Lua reads Redis TIME, computes
 * the member deadlines (now + lifetime), prunes with the same Redis now,
 * and EXPIREATs the keys against the same deadlines. The authoritative
 * challenge record's PHP-clock expiry is deliberately NOT reproduced:
 * a PHP/Redis clock skew can therefore never expire a still-valid member
 * early (the accounting stays conservative by at most the skew plus the
 * mint -> admit interval). Every member's score is its own deadline, so
 * it dies exactly when the accounting says it dies and is never
 * refreshed.
 *
 * The global accounting is an expiry-aware membership, not a cumulative
 * counter: {@see issue()} runs one atomic Lua that prunes expired members
 * with `ZREMRANGEBYSCORE` -inf now and refuses when ZCARD >= the global
 * cap. It then `ZADD`s the minted challenge's nonce scored at its
 * Redis-clock deadline. The membership is therefore genuinely "currently
 * live unresolved challenges". A solve via {@see solved()}, a
 * proven-not-handed-off issuance failure via
 * {@see abortedBeforeHandoff()} and a client cancellation via
 * {@see cancelled()} all ZREM the nonce. A member can never outlive its
 * challenge: the score expires it even if every removal path fails. The
 * global cap is a real bound on live challenges, not a cumulative
 * high-water mark. The per-source bound is the same model, one ZSET per
 * source (the key is the source's own hex pseudonym, computed in PHP on
 * the issuance side and resolved from the sidecar by a plain read on the
 * release side — never constructed inside a script): the issuance script
 * prunes the source ZSET by score and refuses when ZCARD >= the
 * per-source cap, so heterogeneous challenge TTLs cannot reset the source
 * bound's lifetime and expired challenges stop counting immediately.
 * A client cancellation returns the original source's slot too. The
 * issuance sidecar (`outstanding:nonce:<nonce>`) pairs the nonce with
 * the source pseudonym that issued it. The release is one-shot: the
 * live-membership ZREM is the gate, only then is the sidecar read and
 * the ORIGINAL source's ZSET member released. The releaser's own
 * identity is never used, since the identity would be wrong and the
 * request client-controlled. Only the sidecar's original source is
 * released, and only when the global member actually existed. A
 * duplicate release is a no-op, so nothing can ever be double-released.
 *
 * Key-level retention: the ZSET SCORES are the real expiries (a score
 * older than Redis now is dead data, and every prune removes it), but a
 * ZSET key is NOT deleted automatically — without a key TTL, an abandoned
 * source's key (whose name carries the keyed source pseudonym) would stay
 * in Redis forever. Every admission therefore EXPIREATs the source ZSET
 * and the global ZSET at the LATEST live member's deadline plus the
 * cleanup margin (the configured ttl margin), so the key outlives its
 * longest member by exactly the margin and can never accumulate. Because
 * the deadline is derived from the newest member (ZREVRANGE of the max
 * score), the key TTL only ever extends, never shortens, a still-live
 * membership.
 *
 * The `ZREMRANGEBYSCORE` prune is bounded by the ZSET's own size: a
 * member is removed exactly when its score fell below the current time.
 * All ZSETs are bounded by the global cap plus, transiently, the requests
 * between the prune and their `ZADD`; see the issuance script. The
 * `global:live` key is deliberately named apart from the legacy `global`
 * counter key, so a deployment rolling out this accounting never reads a
 * `WRONGTYPE` on the legacy key type while its string counter is still
 * decaying.
 *
 * Every script accesses ONLY keys supplied as KEYS arguments: no
 * programmatically generated key names, no key names derived from stored
 * data. The release side resolves the per-source ZSET key in PHP from a
 * plain sidecar GET (the sidecar's value is the hex pseudonym; the key is
 * the prefix + that hex) and passes it as a declared KEYS argument; the
 * script re-verifies the sidecar against that resolved source before
 * touching the ZSET. The scripts therefore stay inside the EVAL contract
 * on sharded / proxied / Redis Cloud topologies as well as standalone
 * and OSS Cluster (all keys share the one {kiwi:<ns>} hash slot).
 *
 * Verification, see {@see solved()}: one-shot, nonce-authoritative
 * release of the solved nonce from the live membership, the original
 * source membership and the sidecar when a challenge verifies
 * successfully. The nonce is the authoritative member identity, so the
 * solve removes exactly the challenge that was solved. The call is
 * idempotent and safe on retries: only the first removal releases
 * anything. Best-effort by contract: the whole operation — the sidecar
 * read included — sits inside the exception boundary, so a Redis failure
 * can never fail a valid solve; the memberships decay by their deadlines
 * and the same logical operation's later successful observation
 * re-releases.
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
 * never breaks a valid solve; the memberships decay by their Redis-clock
 * deadlines — fail-closed, the caps are overcounted, never undercounted).
 */
final class OutstandingChallenges
{
    /**
     * Atomic check + admit + live-membership add + source sidecar + key
     * retention:
     *   KEYS[1] = {kiwi:<ns>}:outstanding:<hex> (the issuing source's
     *             membership ZSET — one key per source, computed in PHP
     *             from the caller's canonical IP, never inside the script).
     *   KEYS[2] = {kiwi:<ns>}:outstanding:global:live (live-outstanding ZSET).
     *   KEYS[3] = {kiwi:<ns>}:outstanding:nonce:<nonce> (issuance sidecar).
     *   ARGV[1] = per-source cap.
     *   ARGV[2] = global cap (live-outstanding members).
     *   ARGV[3] = sidecar TTL in seconds (challenge lifetime + ttl
     *             margin). The memberships have NO scalar expiry to
     *             reset: their members expire by their Redis-clock
     *             deadlines.
     *   ARGV[4] = the RELATIVE challenge lifetime in seconds. The
     *             membership deadlines are computed inside the script as
     *             Redis TIME + lifetime, so the accounting never expires
     *             a valid member early under PHP/Redis clock skew (the
     *             authoritative record's PHP-clock expiry is deliberately
     *             not reproduced; the accounting stays conservative).
     *   ARGV[5] = the minted challenge nonce, the ZSET member.
     *   ARGV[6] = the issuing source's pseudonym (an HMAC and never a raw
     *             IP). It is stored in the sidecar so a later release
     *             returns exactly this source's slot.
     *   ARGV[7] = the cleanup margin in seconds: the source and global
     *             ZSETs are EXPIREAT'd at the latest live member's
     *             deadline plus this margin, so abandoned keys can never
     *             accumulate in Redis (the scores remain the real
     *             expiries; the key TTL only bounds stale-key retention).
     * Prunes expired members with `ZREMRANGEBYSCORE` -inf now, bounded by
     * the ZSETs' sizes, and counts the source's LIVE members with ZCARD —
     * a score-range primitive with well-defined semantics under the
     * members' differing deadlines. Refuses (0 = source cap, -1 = global
     * cap) before any admission write. A challenge issued with a short
     * TTL expires from the source membership on its own schedule and can
     * never shorten the lifetime of the source's other outstanding
     * challenges. Then `ZADD`s both memberships, `SET`s the sidecar and
     * refreshes both keys' EXPIREAT to the latest deadline plus the
     * margin. A challenge is only returned to the client when the script
     * admitted it, so the bounds can never silently exceed the caps
     * through concurrency.
     */
    private const ISSUE_SCRIPT = <<<'LUA'
-- Outstanding challenge issuance: atomic per-source live ZCARD cap check
-- (score-pruned) + global live cap check + memberships ZADD + source
-- sidecar + key-level retention. All deadlines come from Redis TIME plus
-- the RELATIVE challenge lifetime, so the accounting can never expire a
-- valid member early under PHP/Redis clock skew.
local t = redis.call('TIME')
local now = tonumber(t[1])
local liveUntil = now + tonumber(ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then return -1 end
redis.call('ZADD', KEYS[1], liveUntil, ARGV[5])
redis.call('ZADD', KEYS[2], liveUntil, ARGV[5])
redis.call('SET', KEYS[3], ARGV[6], 'EX', tonumber(ARGV[3]))
-- Key-level retention: a ZSET score is data, not a key expiry — without a
-- key TTL an abandoned source's key (whose name carries the keyed source
-- pseudonym) would stay in Redis forever. EXPIREAT at the LATEST live
-- member's deadline plus the cleanup margin; the newest member's deadline
-- is the max score, so the key TTL only extends, never shortens.
local latest = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
if #latest == 2 then
  redis.call('EXPIREAT', KEYS[1], math.floor(tonumber(latest[2])) + tonumber(ARGV[7]))
end
local latestGlobal = redis.call('ZREVRANGE', KEYS[2], 0, 0, 'WITHSCORES')
if #latestGlobal == 2 then
  redis.call('EXPIREAT', KEYS[2], math.floor(tonumber(latestGlobal[2])) + tonumber(ARGV[7]))
end
return 1
LUA;

    /**
     * The single nonce-authoritative release, shared by solve, client
     * cancellation and proven-not-handed-off issuance abort: the
     * live-membership ZREM is the ONE-SHOT gate; only its removal reads
     * the issuance sidecar, releases the ORIGINAL source's ZSET member
     * and deletes the sidecar. The caller's identity plays no role (a
     * challenge issued through source A and released from source B must
     * release A's slot, never B's — IP binding may be disabled).
     * Duplicate releases are harmless: only the removal of the nonce from
     * the live membership releases anything, and a member that expired
     * away removes nothing. Every accessed key is a declared KEYS
     * argument — the per-source ZSET key (KEYS[3]) is resolved by the
     * caller from a plain sidecar read, never constructed from stored
     * data inside the script, and the script re-verifies the sidecar
     * against the caller's resolved source (ARGV[2]) before touching it,
     * so the EVAL contract holds on standalone, OSS Cluster and stricter
     * sharded/proxied topologies.
     *   KEYS[1] = the global live-outstanding ZSET.
     *   KEYS[2] = the nonce's issuance sidecar.
     *   KEYS[3] = the ORIGINAL source's membership ZSET (the caller's
     *             plain-read resolution; re-verified inside the script).
     *   ARGV[1] = the released challenge nonce.
     *   ARGV[2] = the source pseudonym the caller resolved (must equal
     *             the sidecar's value for the release to proceed).
     */
    private const RELEASE_SCRIPT = <<<'LUA'
-- Outstanding challenge release (solve / cancel / aborted-before-handoff):
-- one-shot ZREM-gated release of the ORIGINAL source's ZSET member +
-- sidecar DEL. All keys are declared; the source resolution is re-verified
-- against the sidecar.
local removed = redis.call('ZREM', KEYS[1], ARGV[1])
if removed == 1 then
  local source = redis.call('GET', KEYS[2])
  if source and source ~= '' and source == ARGV[2] then
    redis.call('ZREM', KEYS[3], ARGV[1])
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
     *   KEYS[2] = {kiwi:<ns>}:cancel:global (deployment-global window ZSET).
     *   ARGV[1] = per-IP cap.
     *   ARGV[2] = window in ms.
     *   ARGV[3] = unique request id (ZSET member).
     *   ARGV[4] = deployment-global cap.
     * Returns 1 when both windows have room, 0 when the per-source cap is
     * exhausted, -1 when the deployment-global cap is exhausted (after
     * pruning expired hits). A Redis failure propagates: the caller fails
     * closed.
     */
    private const CANCEL_ADMISSION_SCRIPT = <<<'LUA'
-- Outstanding challenge cancellation admission: per-source sliding window
-- PLUS a deployment-global window. The global cap bounds the total
-- cancellation request rate across every source (an attacker rotating IPs
-- cannot force unlimited random-nonce storage lookups and source-limiter
-- key churn); the per-source cap bounds any single source. No request
-- touches storage before this succeeds.
local time = redis.call('TIME')
local now = tonumber(time[1])*1000 + math.floor(tonumber(time[2])/1000)
local cutoff = now - tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', cutoff)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then return -1 end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('ZADD', KEYS[2], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) + 1000)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[2]) + 1000)
return 1
LUA;

    /** The cancellation endpoint's per-source sliding window, ms. */
    public const CANCELLATION_WINDOW_MS = 60_000;

    /** The cancellation endpoint's per-source cap per window. */
    public const CANCELLATION_PER_IP_CAP = 120;

    /** The cancellation endpoint's deployment-global cap per window. */
    public const CANCELLATION_GLOBAL_CAP = 20_000;

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
     * @param int                   $ttlMarginSecs   extra retention beyond
     *                                               token validity: the
     *                                               sidecar EX basis AND the
     *                                               key-level cleanup margin
     *                                               (the source/global ZSETs
     *                                               are EXPIREAT'd at the
     *                                               latest live member's
     *                                               deadline plus this
     *                                               margin). The memberships
     *                                               expire by their
     *                                               Redis-clock deadlines,
     *                                               never by this margin.
     * @param int                   $waitReplicas    when > 0, a SUCCESSFUL
     *                                               admission (the source/
     *                                               global memberships + the
     *                                               sidecar landed) is
     *                                               followed by a verified
     *                                               Redis WAIT whose
     *                                               acknowledgement count is
     *                                               checked — the challenge
     *                                               is only handed out once
     *                                               the admission write
     *                                               reached the configured
     *                                               replica count, so an
     *                                               asymmetric failover can
     *                                               never resurrect a
     *                                               valid-but-unaccounted
     *                                               challenge record (which
     *                                               would let redemptions
     *                                               exceed the hard
     *                                               outstanding caps).
     *                                               Fewer than waitReplicas
     *                                               acked replicas raise
     *                                               {@see ReplicaWaitException}.
     *                                               Supported on standalone
     *                                               Redis connections only,
     *                                               the same matrix as the
     *                                               core RedisStorage and
     *                                               the disposition store.
     *                                               The RELEASE side stays
     *                                               best-effort and never
     *                                               WAITs: a lost release
     *                                               write overcounts
     *                                               (fail-closed), so the
     *                                               success path never
     *                                               depends on replica
     *                                               acknowledgement.
     * @param int                   $waitTimeoutMs   WAIT timeout in ms (default
     *                                               100).
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $redis,
        private readonly string $keyPrefix,
        private readonly RiskKeys $keys,
        private readonly int $maxPerSource,
        private readonly int $maxGlobal,
        private readonly int $ttlMarginSecs = 0,
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
    ) {
        $this->refuseVerifiedWaitOnUnsupportedPredisClients();
    }

    /**
     * The per-source membership ZSET key for a client IP: the raw IP never
     * appears in Redis, only the hex form of
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
     * The per-source pseudonym (the hex HMAC) for a client IP — the
     * sourceKey() suffix, what the issuance sidecar stores.
     */
    public function sourcePseudonym(string $clientIp): string
    {
        return substr($this->sourceKey($clientIp), \strlen($this->keyPrefix));
    }

    /**
     * Admit one issued challenge. The script atomically checks both caps
     * against the LIVE memberships (pruned of expired members, so a
     * heterogeneous challenge TTL can never reset the source bound's
     * lifetime), then adds the minted nonce to the per-source and global
     * memberships scored at its Redis-clock deadline (Redis TIME + the
     * RELATIVE lifetime — the accounting stays in one clock domain and
     * can never expire a still-valid member early under PHP/Redis clock
     * skew), writes the issuance sidecar (the nonce -> original source
     * pseudonym) and refreshes both keys' EXPIREAT to the latest deadline
     * plus the cleanup margin, so an abandoned source's key can never
     * accumulate. The challenge must already be minted: the ZSET members
     * are the nonce and their scores the deadlines, which exist only once
     * the record is minted. The admission runs before handoff, so a
     * refused admission never hands out (the caller discards the minted
     * record). The sidecar stores only the HMAC source pseudonym, never
     * a raw IP, and lets the release paths return exactly the source that
     * issued the challenge.
     *
     * @param string $clientIp         the canonical client IP.
     * @param string $nonce            the minted challenge's nonce (the
     *                                 live-membership member).
     * @param int    $challengeTtlSecs the RELATIVE challenge lifetime,
     *                                 seconds. The membership deadline is
     *                                 computed from Redis TIME inside the
     *                                 script, so the accounting is
     *                                 conservative under clock skew and
     *                                 never expires a valid member early.
     *
     * @return int 1 = admitted, 0 = per-source cap reached, -1 = global cap
     *              reached (no admission write on refusal; expired members
     *              are pruned either way).
     *
     * @throws \Throwable when Redis fails (fail closed, so the caller
     *                    refuses issuance rather than minting an unchecked
     *                    challenge)
     */
    public function issue(string $clientIp, string $nonce, int $challengeTtlSecs): int
    {
        $ttl = $challengeTtlSecs + $this->ttlMarginSecs;
        $sourceZset = $this->sourceKey($clientIp);
        $global = $this->keyPrefix.'global:live';
        $sidecar = $this->keyPrefix.'nonce:'.$nonce;

        $admitted = (int) $this->eval(self::ISSUE_SCRIPT, [$sourceZset, $global, $sidecar], [
            (string) $this->maxPerSource,
            (string) $this->maxGlobal,
            (string) max(1, $ttl),
            (string) max(1, $challengeTtlSecs),
            $nonce,
            substr($sourceZset, \strlen($this->keyPrefix)),
            (string) $this->ttlMarginSecs,
        ]);

        // Durability barrier: only the admission WRITE needs the
        // guarantee (undercount prevention — an un-replicated admission
        // would let a promotion resurrect a valid-but-unaccounted
        // challenge); a refused admission performed no write and never
        // WAITs.
        if ($admitted === 1 && $this->waitReplicas > 0) {
            $this->waitAndVerify('the outstanding admission');
        }

        return $admitted;
    }

    /**
     * One-shot, nonce-authoritative release: removes the solved nonce
     * from the live membership, and only when the removal actually
     * happened, reads the nonce's issuance sidecar and releases the
     * ORIGINAL source's ZSET member, then drops the sidecar. The caller's
     * IP is never used; a duplicate solve (ZREM == 0) releases nothing.
     * The per-source ZSET key is resolved from a plain sidecar read (the
     * sidecar's pseudonym is a key SUFFIX, never a script-derived key
     * name) and handed to the script as a declared key, which re-verifies
     * it. Best-effort BY CONTRACT: the sidecar read and the script both
     * sit inside the exception boundary, so a Redis failure can never
     * fail a valid solve (the memberships decay by their deadlines
     * otherwise, and the same logical operation's retry re-releases —
     * fail-closed, the caps are overcounted, never undercounted).
     */
    public function solved(string $nonce): void
    {
        $this->release($nonce);
    }

    /**
     * Nonce-authoritative release when an admitted challenge was proven
     * never handed out (the controller's proven-not-handed-out failure
     * paths): the exact same one-shot model as solve and cancellation —
     * the nonce's live membership is removed and only that removal
     * releases the original source's ZSET member and drops the sidecar.
     * The source slot is returned so a crashed issuance does not
     * silently consume the source's stockpile budget. The nonce leaves
     * the deployment-wide live membership so an abandoned challenge
     * never counts against the global cap, and its issuance sidecar is
     * dropped. Best-effort by contract (the whole operation sits inside
     * the exception boundary): a failed rollback must never change the
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
        $this->release($nonce);
    }

    /**
     * One-shot live-membership removal + original-source slot release for
     * a client-cancelled challenge. Called by the cancellation endpoint
     * after the record's atomic pending->cancelled transition
     * (CancellableStorageInterface). The ZREM gate makes it idempotent:
     * cancelling a nonce with no live member (never issued, expired away,
     * or already removed by a solve/abort/cancellation) is a no-op. The
     * original source ZSET member (from the issuance sidecar, never the
     * canceller's IP) is released exactly once per issued challenge.
     * Best-effort by contract: the storage transition may already have
     * committed before a Redis accounting failure, and the cancellation
     * response must still succeed.
     */
    public function cancelled(string $nonce): void
    {
        $this->release($nonce);
    }

    public function confirmReplication(string $what): void
    {
        if ($this->waitReplicas <= 0) {
            return;
        }
        $this->waitAndVerify($what);
    }

    /**
     * Whether the source may send another cancellation request: the
     * endpoint's bounded per-IP limiter (a sliding window, pruned and
     * checked atomically). Throws on a Redis failure (fail closed — the
     * endpoint refuses rather than letting an unbounded cancellation
     * stream through).
     */
    public function cancellationAdmission(string $clientIp): int
    {
        $source = $this->sourceKey($clientIp);
        $window = $this->keyPrefix.'cancel:'.substr($source, \strlen($this->keyPrefix));

        return (int) $this->eval(self::CANCEL_ADMISSION_SCRIPT, [$window, $this->keyPrefix.'cancel:global'], [
            (string) self::CANCELLATION_PER_IP_CAP,
            (string) self::CANCELLATION_WINDOW_MS,
            bin2hex(random_bytes(16)),
            (string) self::CANCELLATION_GLOBAL_CAP,
        ]);
    }

    /**
     * The one best-effort release primitive shared by solve, cancellation
     * and aborted-before-handoff: EVERYTHING — the plain sidecar read and
     * the declared-key script — sits inside the exception boundary, so a
     * Redis failure can never break the caller's success path. The
     * memberships decay by their Redis-clock deadlines otherwise
     * (fail-closed: the caps are overcounted, never undercounted) and the
     * same logical operation's later successful observation re-releases.
     */
    private function release(string $nonce): void
    {
        try {
            $sidecar = $this->keyPrefix.'nonce:'.$nonce;
            $source = $this->redis->get($sidecar);
            if (!\is_string($source) || $source === '') {
                // No sidecar: the challenge was never admitted or its
                // release already happened — nothing to gate on, nothing
                // to release.
                return;
            }
            $this->eval(self::RELEASE_SCRIPT, [
                $this->keyPrefix.'global:live',
                $sidecar,
                $this->keyPrefix.$source,
            ], [$nonce, $source]);
        } catch (\Throwable) {
            // Best-effort by contract.
        }
    }

    /**
     * Block until at least waitReplicas replicas acknowledged the previous
     * write, and fail closed when they did not (the same contract as the
     * core RedisStorage and the disposition store).
     */
    private function waitAndVerify(string $what): void
    {
        if ($this->redis instanceof \Redis) {
            $acked = $this->redis->rawCommand('WAIT', $this->waitReplicas, $this->waitTimeoutMs);
        } else {
            $acked = $this->redis->executeRaw(['WAIT', $this->waitReplicas, $this->waitTimeoutMs]);
        }
        if ($acked === false || $acked === null) {
            throw new ReplicaWaitException(sprintf(
                'Redis WAIT failed after %s (waitReplicas=%d, timeout=%dms)',
                $what,
                $this->waitReplicas,
                $this->waitTimeoutMs,
            ));
        }
        if ((int) $acked < $this->waitReplicas) {
            throw new ReplicaWaitException(sprintf(
                'Redis WAIT acknowledged %d of %d requested replicas after %s',
                (int) $acked,
                $this->waitReplicas,
                $what,
            ));
        }
    }

    /**
     * Refuse the verified-WAIT hardening on Predis clients whose command
     * dispatch can hide or re-execute the durability-critical write (the
     * same refusal the core RedisStorage and the disposition store
     * apply): WAIT is connection-relative, so a replication aggregate's
     * failure retry can re-execute the WAIT on a replacement connection
     * whose write offset is empty, a cluster aggregate cannot route a
     * keyless WAIT, and a retry-enabled standalone client can
     * transparently re-execute the Lua mutation after a lost response.
     * Supported topology is standalone Redis only.
     */
    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        \KiwiCaptcha\VerifiedWaitGuard::refuseUnsupported($this->redis, $this->waitReplicas, 'OutstandingChallenges');
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
