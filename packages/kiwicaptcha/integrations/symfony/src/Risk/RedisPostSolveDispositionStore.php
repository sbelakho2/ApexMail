<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;

/**
 * Redis-backed durable post-solve disposition store.
 *
 * Key: `{kiwi:<namespace>}:postsolve:<nonce>` (the nonce is random
 * security state — no HMAC). Value: JSON
 *   pending:  {"v":1,"state":"pending","owner":...,"lease_until":...,"disposition":null,"decision_id":...}
 *   complete: {"v":1,"state":"complete","owner":null,"lease_until":null,
 *              "disposition":{"kind":"chain_required","decision_id":...,"chain_id":...},
 *              "decision_id":...}
 * Record TTL: the constructor's configured TTL (the extension wires
 * Config::MAX_TTL_SECS + risk.redis.ttl_margin_secs) — the disposition
 * survives at least as long as the consumed core result can be replayed;
 * the per-call claim TTL applies when no configured TTL is given.
 *
 * The claim is ONE atomic Lua state machine (missing -> pending(me,
 * lease); pending+me -> 'pending'; pending+other+live -> 'pending' (busy);
 * pending+other+expired -> takeover -> 'taken_over'; complete ->
 * 'complete'): at most one owner computes a nonce's disposition. The
 * SHORT FIXED lease (15 s) bounds the in-flight window — never the record
 * TTL. The finalize is atomic too: pending(me) -> complete, refused for a
 * non-owner or a non-pending record, so a crash-taken-over computation
 * can never overwrite a completed disposition and a replayed proof
 * reproduces the persisted final disposition. The pending record carries
 * the ORIGINAL decision handle the first owner consumed (claim's
 * decision_id); a TAKEOVER keeps it — a completed disposition survives
 * the crash of its first owner with the original decision id.
 *
 * Every record is decoded ALL-OR-NOTHING against the strict v1 schema
 * ({@see self::decodeRecord()}): a missing/malformed field or a
 * state-invariant violation throws
 * {@see MalformedPostSolveDispositionException} — NEVER a defaulted
 * record (an unknown state never becomes pending, a corrupt kind never
 * Pass, a missing disposition never a silent pass). The same decode runs
 * on the in-memory store, so Array and Redis observe one machine.
 */
final class RedisPostSolveDispositionStore implements PostSolveDispositionStore
{
    private const PREFIX = 'postsolve:';

    /** The SHORT FIXED computation lease — a contention bound, never the record TTL. */
    private const LEASE_SECS = 15;

    /** The chain id shape (base64url of 16 random bytes — the ticket service's alphabet). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /**
     * Single-Lua claim: one atomic transition per nonce.
     *   KEYS[1] = {kiwi:<ns>}:postsolve:<nonce>
     *   ARGV[1] = owner token, ARGV[2] = lease seconds, ARGV[3] = record TTL,
     *   ARGV[4] = the ORIGINAL decision handle ('' = none)
     * Returns 'claimed' | 'pending' | 'taken_over' | 'complete'.
     * A TAKEOVER keeps the persisted decision_id (the original owner's
     * handle — the new owner's GETDEL is empty after the first owner
     * consumed the mapping), so a completed disposition survives the
     * crash of its first owner with the original decision id.
     */
    private const CLAIM_LUA = <<<'LUA'
-- Post-solve disposition claim: single-writer per nonce.
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', KEYS[1])
if not existing then
  local rec = {}
  rec['v'] = 1
  rec['state'] = 'pending'
  rec['owner'] = ARGV[1]
  rec['lease_until'] = now + tonumber(ARGV[2])
  rec['disposition'] = cjson.null
  if ARGV[4] == '' then
    rec['decision_id'] = cjson.null
  else
    rec['decision_id'] = ARGV[4]
  end
  redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', tonumber(ARGV[3]))
  return 'claimed'
end
local rec = cjson.decode(existing)
if rec['v'] ~= 1 then
  return 'pending'
end
if rec['state'] == 'complete' then
  return 'complete'
end
if rec['owner'] == ARGV[1] then
  return 'pending'
end
if tonumber(rec['lease_until']) > now then
  return 'pending'
end
rec['owner'] = ARGV[1]
rec['lease_until'] = now + tonumber(ARGV[2])
rec['disposition'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'taken_over'
LUA;

    /**
     * Atomic finalize: pending(me) -> complete(disposition), keeping the
     * record TTL (KEEPTTL, Redis 6.0+). Refused (false) for a non-owner or
     * a non-pending record — never overwrites another owner's work. The
     * record's decision_id is PRESERVED (the original handle survives in
     * the complete record).
     *   KEYS[1] = the record key
     *   ARGV[1] = owner token, ARGV[2] = disposition JSON
     */
    private const FINALIZE_LUA = <<<'LUA'
-- Post-solve disposition finalize: pending(owner) -> complete.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
local rec = cjson.decode(existing)
if rec['v'] ~= 1 then
  return false
end
if rec['state'] ~= 'pending' then
  return false
end
if rec['owner'] ~= ARGV[1] then
  return false
end
rec['state'] = 'complete'
rec['owner'] = cjson.null
rec['lease_until'] = cjson.null
rec['disposition'] = cjson.decode(ARGV[2])
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return true
LUA;

    /**
     * @param \Predis\Client|\Redis $redis      the Redis client shared with
     *                                          the risk state
     * @param string                $namespace  the risk namespace (the
     *                                          hash-tag discriminator)
     * @param int                   $ttlSecs    the RECORD TTL (the extension
     *                                          wires Config::MAX_TTL_SECS +
     *                                          ttl margin); 0 = use the
     *                                          per-call claim TTL
     */
    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwi',
        private readonly int $ttlSecs = 0,
    ) {
    }

    public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionId = null): string
    {
        // STRICT PRE-READ: an existing record must strictly decode BEFORE
        // the Lua machine may transition it — a corrupt server record
        // throws (fail closed), it is NEVER healed into valid state by a
        // takeover and never answered as a valid disposition.
        $existing = $this->redis->get($this->key($nonce));
        if (\is_string($existing) && $existing !== '') {
            self::decodeRecord($existing);
        }

        $recordTtl = max(1, $this->ttlSecs > 0 ? $this->ttlSecs : $ttlSeconds);
        $status = RedisEval::eval($this->redis, self::CLAIM_LUA, $this->key($nonce), [
            $owner,
            (string) self::LEASE_SECS,
            (string) $recordTtl,
            $decisionId ?? '',
        ]);

        return \is_string($status) && \in_array($status, ['claimed', 'pending', 'taken_over', 'complete'], true)
            ? $status
            : 'pending';
    }

    public function read(string $nonce): ?PostSolveDispositionRecord
    {
        $raw = $this->redis->get($this->key($nonce));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $rec = self::decodeRecord($raw);
        $decisionId = $rec['decision_id'] ?? null;
        if ($rec['state'] === 'pending') {
            return new PostSolveDispositionRecord('pending', $rec['owner'], $rec['lease_until'], null, $decisionId);
        }

        $disposition = $rec['disposition'];

        return new PostSolveDispositionRecord(
            'complete',
            null,
            null,
            new PostSolveDisposition(
                PostSolveDispositionKind::from($disposition['kind']),
                $disposition['decision_id'] ?? null,
                $disposition['chain_id'] ?? null,
            ),
            $decisionId,
        );
    }

    public function finalize(string $nonce, string $owner, PostSolveDisposition $disposition): bool
    {
        $ok = RedisEval::eval($this->redis, self::FINALIZE_LUA, $this->key($nonce), [
            $owner,
            (string) json_encode(self::wire($disposition), JSON_THROW_ON_ERROR),
        ]);

        return $ok === true || $ok === 1;
    }

    private function key(string $nonce): string
    {
        return sprintf('{kiwi:%s}:%s%s', $this->namespace, self::PREFIX, $nonce);
    }

    /**
     * The strict v1 decode — ALL-OR-NOTHING: a missing/malformed field or
     * a state-invariant violation throws
     * {@see MalformedPostSolveDispositionException} (NEVER defaults: an
     * unknown state never becomes pending, a corrupt kind never Pass, a
     * missing disposition never a silent pass). Validates: schema version
     * 1; the exact state enum (pending|complete — nothing else); a
     * non-empty string owner and an integer lease_until REQUIRED in
     * pending and NULL in complete; the disposition field REQUIRED (with
     * a valid kind enum and well-shaped decision_id/chain_id) in complete
     * and NULL in pending; a non-empty string-or-null decision handle in
     * both states.
     *
     * @return array<string, mixed> the validated record
     *
     * @throws MalformedPostSolveDispositionException
     */
    private static function decodeRecord(string $raw): array
    {
        try {
            $rec = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record is not valid JSON', 0, $e);
        }
        if (!\is_array($rec)) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record must be a JSON object');
        }
        if (($rec['v'] ?? null) !== 1) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record schema version must be 1');
        }
        $state = $rec['state'] ?? null;
        if (!\is_string($state) || !\in_array($state, ['pending', 'complete'], true)) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record state must be pending|complete');
        }
        $owner = $rec['owner'] ?? null;
        $leaseUntil = $rec['lease_until'] ?? null;
        $disposition = $rec['disposition'] ?? null;
        if ($state === 'pending') {
            if (!\is_string($owner) || $owner === '') {
                throw new MalformedPostSolveDispositionException('post-solve disposition record owner is required in the pending state');
            }
            if (!\is_int($leaseUntil)) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record lease_until must be an integer in the pending state');
            }
            if ($disposition !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record disposition must be null in the pending state');
            }
        } else {
            if ($owner !== null || $leaseUntil !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record owner/lease_until must be null in the complete state');
            }
            if (!\is_array($disposition)) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record disposition is required in the complete state');
            }
            $kind = $disposition['kind'] ?? null;
            if (!\is_string($kind) || PostSolveDispositionKind::tryFrom($kind) === null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record kind must be a valid disposition kind');
            }
            $decisionId = $disposition['decision_id'] ?? null;
            if ($decisionId !== null && (!\is_string($decisionId) || $decisionId === '')) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
            }
            $chainId = $disposition['chain_id'] ?? null;
            if ($chainId !== null && (!\is_string($chainId) || preg_match(self::CHAIN_ID_PATTERN, $chainId) !== 1)) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_id must match the chain id shape or be null');
            }
            if ($kind === PostSolveDispositionKind::ChainRequired->value && ($chainId === null || $chainId === '')) {
                throw new MalformedPostSolveDispositionException('a ChainRequired disposition must carry a chain id');
            }
            if ($kind !== PostSolveDispositionKind::ChainRequired->value && $chainId !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_id must be null outside the ChainRequired kind');
            }
        }
        $recordDecisionId = $rec['decision_id'] ?? null;
        if ($recordDecisionId !== null && (!\is_string($recordDecisionId) || $recordDecisionId === '')) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
        }

        return $rec;
    }

    /**
     * The persisted disposition shape — kind / decision_id / chain_id
     * ONLY. Raw risk vectors, fingerprints and descriptors are never
     * stored.
     *
     * @return array{kind: string, decision_id: ?string, chain_id: ?string}
     */
    private static function wire(PostSolveDisposition $disposition): array
    {
        return [
            'kind' => $disposition->kind->value,
            'decision_id' => $disposition->decisionId,
            'chain_id' => $disposition->chainId,
        ];
    }
}
