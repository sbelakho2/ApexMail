<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;

/**
 * Redis-backed durable post-solve disposition store.
 *
 * Key: `{kiwi:<namespace>}:postsolve:<nonce>` (the nonce is random
 * security state, no hmac). Value: json
 *   pending:  {"v":1,"state":"pending","owner":...,"lease_until":...,"disposition":null,"decision_id":...}
 *   complete: {"v":1,"state":"complete","owner":null,"lease_until":null,
 *              "disposition":{"kind":"chain_required","decision_id":...,"chain_id":...,"chain_expires_at":...},
 *              "decision_id":...}.
 * Record TTL: the constructor's configured TTL (the extension wires
 * Config::MAX_TTL_secs + risk.redis.ttl_margin_secs). The disposition
 * survives at least as long as the consumed core result can be replayed;
 * the per-call claim TTL applies when no configured TTL is given.
 *
 * The claim is one atomic Lua state machine, missing -> pending(me,
 * lease), pending+me -> 'pending', pending+other+live -> 'pending' (busy),
 * pending+other+expired -> takeover -> 'taken_over', complete ->
 * 'complete', so at most one owner computes a nonce's disposition. The
 * claim response carries the claim outcome AND the record the caller
 * needs (the pending record on claimed/taken_over, the complete record
 * on complete), so the caller runs claim -> compute -> finalize with no
 * separate read. The machine reads the existing state before touching
 * anything else: a complete claim, a busy claim and a takeover never
 * touch the nonce -> decision mapping key. Only the missing path
 * consumes it, with getdel inside the script and at most one winner, and
 * persists the paired decision id in the pending record in the same
 * transition. A strict existing-record validation runs inside the claim
 * before any transition: a corrupt record answers 'corrupt' and throws
 * (fail closed), never healed into valid state by a takeover and never
 * answered as a valid disposition. A fallible pre-read is no longer
 * needed, so the common fresh path is exactly two interactions. The
 * short fixed lease (15 s) bounds the in-flight window, never the record
 * TTL. The finalize is atomic too: pending(me) -> complete, refused for
 * a non-owner or a non-pending record, so a crash-taken-over computation
 * can never overwrite a completed disposition and a replayed proof
 * reproduces the persisted final disposition. The pending record carries
 * the original decision handle the first owner's claim consumed; a
 * takeover keeps it, so a completed disposition survives the crash of
 * its first owner with the original decision id.
 *
 * Every record is decoded all-or-nothing against the strict schema, see
 * {@see self::decodeRecord()}: a missing/malformed field or a
 * state-invariant violation throws
 * {@see MalformedPostSolveDispositionException}, never a defaulted
 * record. An unknown state never becomes pending, a corrupt kind never
 * Pass, a missing disposition never a silent pass, and a ChainRequired
 * record without its chain_expires_at bound never a ticket. The decoder
 * accepts both schema versions 1 and 2: new writes are v1, where
 * chain_required carries chain_expires_at, a shape an earlier release
 * already reads. A v1 chain_required record without chain_expires_at is
 * a legacy record: its carried expiry is null, and the signing falls
 * back to the exact chain record's server-held bound, never corrupt.
 * Any other v1 violation stays corrupt, and a v2 chain_required record
 * requires a positive chain_expires_at, the forward-looking v2
 * acceptance. The same decode runs on the in-memory store, so Array and
 * Redis observe one machine.
 */
final class RedisPostSolveDispositionStore implements PostSolveDispositionStore
{
    private const PREFIX = 'postsolve:';

    /** The short fixed computation lease — a contention bound, never the record TTL. */
    private const LEASE_SECS = 15;

    /** The chain id shape (base64url of 16 random bytes — the ticket service's alphabet). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /**
     * Single-Lua claim: one atomic transition per nonce.
     *   keys[1] = {kiwi:<ns>}:postsolve:<nonce>.
     *   keys[2] = the nonce -> decision mapping key
     *             ({kiwi:<ns>}:decision:<nonce>), '' = none (no decision
     *             transfer).
     *   argv[1] = owner token, argv[2] = lease seconds, argv[3] = record
     *             TTL.
     * Returns a JSON object {status, record}: status is
     * 'claimed' | 'pending' | 'taken_over' | 'complete' | 'corrupt'. The
     * record field carries the record the caller needs for that outcome:
     * the pending record on claimed/taken_over (the consumed decision
     * handle), and the complete record on complete. The caller then runs
     * claim -> compute -> finalize with no separate read. The existing
     * state is read first and answered without touching the decision key:
     * complete -> 'complete'; pending+live other owner -> 'pending'; an
     * expired-lease takeover -> 'taken_over'. A takeover preserves the
     * existing record's decision_id, since it never GETDELs a fresh
     * mapping. Only the missing path consumes the mapping, with getdel
     * atomic with the creation and at most one winner, and persists the
     * paired decision id in the pending record in the same transition.
     * A corrupt existing record is refused fail-closed with 'corrupt'
     * before any mutation. It is never healed into valid state by a
     * takeover and never answered as a valid disposition. The complete
     * record's disposition shape is validated by the store's strict
     * decoder on the read-only response.
     */
    private const CLAIM_LUA = <<<'LUA'
-- Post-solve disposition claim: single-writer per nonce.
-- The existing state answers FIRST — complete/busy/takeover NEVER touch
-- the nonce -> decision mapping; ONLY the missing path consumes it
-- (GETDEL) atomically with the pending-record creation. The response
-- carries the claim outcome AND the record the caller needs (the
-- pending record on claimed/taken_over, the complete record on
-- complete), so the caller performs claim -> compute -> finalize with
-- no separate read. A corrupt existing record is refused fail-closed
-- ('corrupt') before any mutation — never healed by a takeover, never
-- answered as a valid disposition.
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', KEYS[1])
if not existing then
  local decisionId = cjson.null
  if KEYS[2] ~= '' then
    local d = redis.call('GETDEL', KEYS[2])
    if d then
      local ok, decoded = pcall(cjson.decode, d)
      if ok and type(decoded) == 'table' and type(decoded['decision_id']) == 'string' and decoded['decision_id'] ~= '' then
        decisionId = decoded['decision_id']
      end
    end
  end
  local rec = {}
  rec['v'] = 1
  rec['state'] = 'pending'
  rec['owner'] = ARGV[1]
  rec['lease_until'] = now + tonumber(ARGV[2])
  rec['disposition'] = cjson.null
  rec['decision_id'] = decisionId
  redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', tonumber(ARGV[3]))
  return cjson.encode({ status = 'claimed', record = rec })
end
local rec = cjson.decode(existing)
-- Strict existing-record validation (fail closed, never healed): an
-- unknown schema or state, or a pending record without a well-shaped
-- owner/lease/deferred disposition/decision handle, is corrupt and
-- answers 'corrupt' before any transition. The complete record's
-- disposition shape is validated by the store's strict decoder on the
-- read-only response.
if rec['v'] ~= 1 and rec['v'] ~= 2 then
  return cjson.encode({ status = 'corrupt' })
end
if rec['state'] == 'complete' then
  return cjson.encode({ status = 'complete', record = rec })
end
if rec['state'] ~= 'pending' then
  return cjson.encode({ status = 'corrupt' })
end
if type(rec['owner']) ~= 'string' or rec['owner'] == '' then
  return cjson.encode({ status = 'corrupt' })
end
if type(rec['lease_until']) ~= 'number' then
  return cjson.encode({ status = 'corrupt' })
end
if rec['disposition'] ~= nil and rec['disposition'] ~= cjson.null then
  return cjson.encode({ status = 'corrupt' })
end
local decisionId = rec['decision_id']
if decisionId ~= nil and decisionId ~= cjson.null and (type(decisionId) ~= 'string' or decisionId == '') then
  return cjson.encode({ status = 'corrupt' })
end
if rec['owner'] == ARGV[1] then
  return cjson.encode({ status = 'pending' })
end
if tonumber(rec['lease_until']) > now then
  return cjson.encode({ status = 'pending' })
end
rec['owner'] = ARGV[1]
rec['lease_until'] = now + tonumber(ARGV[2])
rec['disposition'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return cjson.encode({ status = 'taken_over', record = rec })
LUA;

    /**
     * Atomic finalize: pending(me) -> complete(disposition), keeping the
     * record TTL (keepttl, Redis 6.0+). Refused (false) for a non-owner or
     * a non-pending record — never overwrites another owner's work. The
     * record's decision_id is preserved (the original handle survives in
     * the complete record).
     *   keys[1] = the record key
     *   argv[1] = owner token, argv[2] = disposition json
     */
    private const FINALIZE_LUA = <<<'LUA'
-- Post-solve disposition finalize: pending(owner) -> complete.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
local rec = cjson.decode(existing)
if rec['v'] ~= 1 and rec['v'] ~= 2 then
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
     * @param int                   $ttlSecs    the record TTL (the extension
     *                                          wires Config::MAX_TTL_secs +
     *                                          ttl margin); 0 = use the
     *                                          per-call claim TTL
     */
    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwi',
        private readonly int $ttlSecs = 0,
    ) {
    }

    public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionKey = null): array
    {
        // The strict existing-record validation runs inside the claim
        // Lua (fail closed before any transition) and the claim response
        // carries the record the caller needs — a corrupt server record
        // throws (fail closed), it is never healed into valid state by a
        // takeover and never answered as a valid disposition, and the
        // caller performs claim -> compute -> finalize with no separate
        // read round-trip.
        $recordTtl = max(1, $this->ttlSecs > 0 ? $this->ttlSecs : $ttlSeconds);
        $payload = $this->evalScript(self::CLAIM_LUA, [
            $this->key($nonce),
            $decisionKey ?? '',
        ], [
            $owner,
            (string) self::LEASE_SECS,
            (string) $recordTtl,
        ]);

        try {
            $data = json_decode((string) $payload, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new MalformedPostSolveDispositionException('post-solve disposition claim returned an unreadable response');
        }
        if (!\is_array($data) || !\is_string($data['status'] ?? null)) {
            throw new MalformedPostSolveDispositionException('post-solve disposition claim returned an unreadable response');
        }
        if ($data['status'] === 'corrupt') {
            throw new MalformedPostSolveDispositionException('post-solve disposition record is malformed');
        }
        if (!\in_array($data['status'], ['claimed', 'pending', 'taken_over', 'complete'], true)) {
            // Defensive fallback for an unknown state-machine answer:
            // fail closed, never defaulted into a valid outcome.
            throw new MalformedPostSolveDispositionException(sprintf('post-solve disposition claim returned an unknown status (%s)', $data['status']));
        }
        $record = null;
        if (isset($data['record']) && \is_array($data['record'])) {
            // The carried record is strictly decoded (the complete
            // disposition shape included) before it is returned, so a
            // corrupt complete record fails closed on the read-only path.
            $record = self::recordFromDecoded(self::validateDecoded($data['record']));
        }

        return [$data['status'], $record];
    }

    /**
     * Run a Lua script against whichever client implementation is in use.
     *
     * @param list<string> $keys
     * @param list<string> $args
     */
    private function evalScript(string $script, array $keys, array $args): mixed
    {
        if ($this->redis instanceof \Redis) {
            // phpredis signature: eval($script, $args, $numKeys)
            return $this->redis->eval($script, [...$keys, ...$args], \count($keys));
        }

        // Predis signature: eval($script, $numkeys, ...$keysAndArgs)
        return $this->redis->eval($script, \count($keys), ...$keys, ...$args);
    }

    public function read(string $nonce): ?PostSolveDispositionRecord
    {
        $raw = $this->redis->get($this->key($nonce));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return self::recordFromDecoded(self::decodeRecord($raw));
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
     * The strict decode, all-or-nothing: a missing/malformed field or a
     * state-invariant violation throws
     * {@see MalformedPostSolveDispositionException}, never defaults. The
     * raw JSON is decoded then validated by {@see self::validateDecoded()}.
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

        return self::validateDecoded($rec);
    }

    /**
     * The strict validation of a decoded record, all-or-nothing: a
     * missing/malformed field or a state-invariant violation throws
     * {@see MalformedPostSolveDispositionException}, never defaults. An
     * unknown state never becomes pending, a corrupt kind never Pass, a
     * missing disposition never a silent pass, and a ChainRequired
     * record without its chain_expires_at bound never a ticket. It
     * validates schema version 1 or 2 within the compatibility window:
     * v2 carries the strict chain_expires_at requirement, and v1
     * additionally accepts a legacy chain_required record without
     * chain_expires_at whose carried expiry is null; every other rule
     * is identical for both versions. The state must be exactly
     * pending|complete. A non-empty string owner and an integer
     * lease_until are required in pending and null in complete. The
     * disposition field is required in complete and null in pending:
     * a valid kind enum and well-shaped decision_id/chain_id, plus the
     * chain_expires_at integer required on the ChainRequired kind, v1
     * legacy excepted, and null outside it. The decision handle must be
     * a non-empty string or null in both states.
     *
     * @param array<string, mixed> $rec
     *
     * @return array<string, mixed> the validated record
     *
     * @throws MalformedPostSolveDispositionException
     */
    private static function validateDecoded(array $rec): array
    {
        $version = $rec['v'] ?? null;
        if ($version !== 1 && $version !== 2) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record schema version must be 1 or 2');
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
            // The ChainRequired record carries its chain's original expiry
            // bound (the signing never re-consults the obligation): under
            // v2 the field is required on the kind and null outside it — a
            // chain_required v2 record without it is malformed state,
            // never a ticket. A v1 chain_required record without
            // chain_expires_at is a legacy record (the shape of the
            // earlier store generation): its carried expiry is null and
            // the signing falls back to the exact chain record's
            // server-held bound — never corrupt. A v1 record that does
            // carry the field must carry a valid positive integer (the
            // shape checks are version-independent).
            $chainExpiresAt = $disposition['chain_expires_at'] ?? null;
            if ($kind === PostSolveDispositionKind::ChainRequired->value) {
                if (!($version === 1 && $chainExpiresAt === null) && (!\is_int($chainExpiresAt) || $chainExpiresAt <= 0)) {
                    throw new MalformedPostSolveDispositionException('a ChainRequired disposition record must carry a positive integer chain_expires_at');
                }
            } elseif ($chainExpiresAt !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_expires_at must be null outside the ChainRequired kind');
            }
        }
        $recordDecisionId = $rec['decision_id'] ?? null;
        if ($recordDecisionId !== null && (!\is_string($recordDecisionId) || $recordDecisionId === '')) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
        }

        return $rec;
    }

    /**
     * Build the typed record from a validated decoded record (the
     * pending claim state + owner + lease deadline + decision handle, or
     * the complete state + persisted disposition + decision handle).
     *
     * @param array<string, mixed> $rec the strict-validated record
     */
    private static function recordFromDecoded(array $rec): PostSolveDispositionRecord
    {
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
                $disposition['chain_expires_at'] ?? null,
            ),
            $decisionId,
        );
    }

    /**
     * The persisted disposition shape — kind / decision_id / chain_id /
     * chain_expires_at only. Raw risk vectors, fingerprints and
     * descriptors are never stored.
     *
     * @return array{kind: string, decision_id: ?string, chain_id: ?string, chain_expires_at: ?int}
     */
    private static function wire(PostSolveDisposition $disposition): array
    {
        return [
            'kind' => $disposition->kind->value,
            'decision_id' => $disposition->decisionId,
            'chain_id' => $disposition->chainId,
            'chain_expires_at' => $disposition->chainExpiresAt,
        ];
    }
}
