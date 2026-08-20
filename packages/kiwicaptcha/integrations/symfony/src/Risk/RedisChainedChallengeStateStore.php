<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Redis-backed chained-challenge state store — the transactional v2
 * contract.
 *
 * Keys (ONE hash-tag family {kiwi:<ns>} — Cluster safe, every script can
 * touch the chain + obligation keys of a transaction atomically):
 *   {kiwi:<ns>}:chain:<chainId>                 the chain record (JSON, v2)
 *   {kiwi:<ns>}:chain-obligation:<obligationId> -> chainId (SAME TTL)
 *
 * The chain lifecycle is the obligation-anchored Lua state machine
 * (available -> reserved(owner, SHORT lease) -> issued(stage2Nonce) with
 * THREE disposition-aware TERMINAL transitions: verified(stage2Nonce) —
 * the PASS transition that ATOMICALLY deletes the obligation mapping only
 * while it still points at this chainId — and step_up_required(nonce) /
 * denied(nonce) — the TERMINAL transitions that KEEP the obligation
 * mapping (the transaction stays bound to its final disposition): the
 * reservation is an OWNER-SCOPED short lease (redis TIME reads the server
 * clock; the lease is min(reservation_lease_secs, the record's OWN
 * remaining TTL) — KEEPTTL — and a record WITHOUT an expiry is corrupted
 * state that fails closed: no lifetime is ever manufactured from the
 * configured TTL), the issuance is an idempotent owner-gated state
 * TRANSITION (never a delete — a retry recovers the issued challenge
 * instead of re-minting), the terminal transitions are idempotent and
 * nonce-pinned (a different nonce is an atomic no-op), and the
 * release/rearm are owner-gated / nonce-pinned atomic no-ops otherwise.
 *
 * Every record is decoded ALL-OR-NOTHING against the strict v2 schema
 * ({@see self::decodeState()}): a missing/malformed field or a
 * state-invariant violation throws
 * {@see MalformedChainedChallengeStateException} — NEVER a defaulted
 * record (a corrupt requiredAction must never become '', policyVersion
 * never 1, chainDepth never 2, state never available). The same decode
 * runs on the in-memory store, so Array and Redis observe one machine.
 */
final class RedisChainedChallengeStateStore implements TransactionalChainedChallengeStateStore
{
    private const PREFIX = 'chain:';

    private const OBLIGATION_PREFIX = 'chain-obligation:';

    /** The Kiwi challenge nonce shape: base64 of 32 random bytes. */
    private const NONCE_PATTERN = '/^[A-Za-z0-9+\/]{43}=$/D';

    /** The canonical scope/identifier shape (the controller's charset). */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

    /** The obligation id: HMAC-SHA256 of the transaction triple, hex. */
    private const OBLIGATION_PATTERN = '/^[0-9a-f]{64}$/D';

    /** The chainable PoW actions (Sha16..Argon64 — never StepUp/Deny). */
    private const CHAINABLE_ACTIONS = ['sha16', 'sha18', 'sha20', 'argon16', 'argon32', 'argon64'];

    private const STATES = ['available', 'reserved', 'issued', 'verified', 'completed', 'step_up_required', 'denied'];

    /**
     * ATOMIC create-or-get over the chain + obligation keys (same hash
     * tag): no obligation -> create the chain (v2 available) + the
     * obligation (same TTL); the obligation exists -> return the existing
     * chain id, RAISING the requiredRank/requiredAction when the new
     * reassessment is stronger (never lowering); the obligation points at
     * a missing/corrupt chain -> compare-delete the stale mapping and
     * create the chain fresh (the retry is inside the script — a stale
     * mapping can never block a transaction).
     */
    private const CREATE_OR_GET_OBLIGATION_LUA = <<<'LUA'
-- Chain obligation create-or-get (chain + obligation, one hash tag).
local existing = redis.call('GET', KEYS[2])
if existing then
  -- The chain the obligation POINTS AT (the value is the bare chain id;
  -- the chain key is derived from the prefix — same hash tag).
  local chained = redis.call('GET', ARGV[11] .. existing)
  if chained then
    local ok, rec = pcall(cjson.decode, chained)
    if ok and type(rec) == 'table' and tonumber(rec['requiredRank']) then
      local newRank = tonumber(ARGV[6])
      if newRank > tonumber(rec['requiredRank']) then
        rec['requiredRank'] = newRank
        rec['requiredAction'] = ARGV[5]
        redis.call('SET', ARGV[11] .. existing, cjson.encode(rec), 'KEEPTTL')
      end
      return existing
    end
  end
  -- stale mapping: compare-delete + create fresh in the SAME script.
  if redis.call('GET', KEYS[2]) == existing then
    redis.call('DEL', KEYS[2])
  end
end
local rec = {
  v = 2,
  stage1Nonce = ARGV[3],
  scope = ARGV[4],
  obligationId = ARGV[1],
  requiredAction = ARGV[5],
  requiredRank = tonumber(ARGV[6]),
  policyVersion = tonumber(ARGV[7]),
  chainDepth = 2,
  state = 'available',
  owner = cjson.null,
  leaseUntil = cjson.null,
  stage2Nonce = cjson.null,
  requestBinding = ARGV[8],
  expiresAt = tonumber(ARGV[9])
}
if rec['requestBinding'] == '' then
  rec['requestBinding'] = cjson.null
end
local ttl = tonumber(ARGV[10])
redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', ttl)
redis.call('SET', KEYS[2], ARGV[2], 'EX', ttl)
return ARGV[2]
LUA;

    /**
     * Owner-scoped reservation with a SHORT lease: available ->
     * reserved(me, now + min(lease, remaining TTL)) — redis TIME for the
     * lease, KEEPTTL preserves the record's OWN remaining TTL (the signed
     * ticket expiry is the true bound). reserved by ME -> 'retry';
     * reserved by another owner with a live lease -> 'busy'; expired
     * lease -> takeover ('taken_over'); issued/verified/completed ->
     * 'issued'/'verified'/'completed'; the TERMINAL step_up_required /
     * denied states answer 'step_up_required'/'denied' (the obligation
     * stays bound — never issue). A record WITHOUT an expiry is CORRUPTED
     * state -> 'missing' (never manufacture a lifetime).
     */
    private const RESERVE_LUA = <<<'LUA'
-- Chain reservation: owner-scoped SHORT lease (redis TIME + remaining TTL).
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- A chain record WITHOUT an expiry is CORRUPTED state: fail closed,
-- never manufacture a lifetime from the configured TTL.
local ttl = tonumber(redis.call('TTL', KEYS[1]))
if ttl <= 0 then
  return 'missing'
end
local rec = cjson.decode(existing)
if rec['state'] == 'issued' then
  return 'issued'
end
if rec['state'] == 'verified' then
  return 'verified'
end
if rec['state'] == 'completed' then
  return 'completed'
end
if rec['state'] == 'step_up_required' then
  return 'step_up_required'
end
if rec['state'] == 'denied' then
  return 'denied'
end
if rec['state'] == 'reserved' then
  if rec['owner'] == ARGV[1] then
    return 'retry'
  end
  if tonumber(rec['leaseUntil']) > now then
    return 'busy'
  end
  local lease = tonumber(ARGV[2])
  if ttl < lease then
    lease = ttl
  end
  rec['state'] = 'reserved'
  rec['owner'] = ARGV[1]
  rec['leaseUntil'] = now + lease
  redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
  return 'taken_over'
end
local lease = tonumber(ARGV[2])
if ttl < lease then
  lease = ttl
end
rec['state'] = 'reserved'
rec['owner'] = ARGV[1]
rec['leaseUntil'] = now + lease
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'available'
LUA;

    /**
     * Idempotent issuance: reserved(me) -> issued(stage2Nonce) (KEEPTTL
     * — a state TRANSITION, never a delete; the issued record lets a
     * retry RECOVER the issued challenge instead of re-minting). Same
     * nonce again -> 'issued_same', verified with the same nonce ->
     * 'verified_same', any other nonce on an issued/completed chain, or
     * any nonce on a TERMINAL step_up_required/denied chain -> 'conflict',
     * a non-owner (or an unreserved chain) -> 'not_owner', absent ->
     * 'missing'.
     */
    private const MARK_ISSUED_LUA = <<<'LUA'
-- Chain issuance: reserved(owner) -> issued(stage2Nonce), idempotent.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
local rec = cjson.decode(existing)
if rec['state'] == 'reserved' then
  if rec['owner'] ~= ARGV[1] then
    return 'not_owner'
  end
  rec['state'] = 'issued'
  rec['stage2Nonce'] = ARGV[2]
  rec['owner'] = cjson.null
  rec['leaseUntil'] = cjson.null
  redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
  return 'issued_new'
end
if rec['state'] == 'issued' or rec['state'] == 'completed' then
  if rec['stage2Nonce'] == ARGV[2] then
    return 'issued_same'
  end
  return 'conflict'
end
if rec['state'] == 'verified' then
  if rec['stage2Nonce'] == ARGV[2] then
    return 'verified_same'
  end
  return 'conflict'
end
if rec['state'] == 'step_up_required' or rec['state'] == 'denied' then
  return 'conflict'
end
return 'not_owner'
LUA;

    /**
     * TERMINAL verification: issued(nonce) -> verified(nonce) (KEEPTTL —
     * the terminal record is kept until its TTL), ATOMICALLY deleting the
     * obligation mapping (KEYS[2]) ONLY if it still points at this
     * chainId. Same nonce again -> 'verified_same'; a different nonce or
     * a non-issuable state -> 'conflict'; absent -> 'missing'.
     */
    private const MARK_VERIFIED_LUA = <<<'LUA'
-- Chain verification: issued(stage2Nonce) -> verified(stage2Nonce), TERMINAL,
-- deleting the obligation mapping only while it still points at this chain.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
local rec = cjson.decode(existing)
if rec['state'] == 'verified' then
  if rec['stage2Nonce'] == ARGV[1] then
    return 'verified_same'
  end
  return 'conflict'
end
if (rec['state'] ~= 'issued' and rec['state'] ~= 'completed') or rec['stage2Nonce'] ~= ARGV[1] then
  return 'conflict'
end
rec['state'] = 'verified'
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
if redis.call('GET', KEYS[2]) == ARGV[2] then
  redis.call('DEL', KEYS[2])
end
return 'verified_new'
LUA;

    /**
     * TERMINAL step-up: issued(nonce) -> step_up_required(nonce) (KEEPTTL
     * — the terminal record is kept until its TTL). The obligation
     * mapping is KEPT: the transaction stays bound to the step-up
     * requirement, so a later challenge request for the same transaction
     * re-encounters the terminal state (never a new stage-1). Same nonce
     * again -> 'step_up_required_same'; a different nonce or a
     * non-issuable state -> 'conflict'; absent -> 'missing'.
     */
    private const MARK_STEP_UP_REQUIRED_LUA = <<<'LUA'
-- Chain step-up: issued(stage2Nonce) -> step_up_required(stage2Nonce), TERMINAL,
-- keeping the obligation mapping (the transaction stays bound to the step-up).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
local rec = cjson.decode(existing)
if rec['state'] == 'step_up_required' then
  if rec['stage2Nonce'] == ARGV[1] then
    return 'step_up_required_same'
  end
  return 'conflict'
end
if (rec['state'] ~= 'issued' and rec['state'] ~= 'completed') or rec['stage2Nonce'] ~= ARGV[1] then
  return 'conflict'
end
rec['state'] = 'step_up_required'
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'step_up_required_new'
LUA;

    /**
     * TERMINAL denial: issued(nonce) -> denied(nonce) (KEEPTTL — the
     * terminal record is kept until its TTL). The obligation mapping is
     * KEPT: the transaction stays bound to its final denial, so a later
     * challenge request for the same transaction re-encounters the
     * terminal state (never a new stage-1). Same nonce again ->
     * 'denied_same'; a different nonce or a non-issuable state ->
     * 'conflict'; absent -> 'missing'.
     */
    private const MARK_DENIED_LUA = <<<'LUA'
-- Chain denial: issued(stage2Nonce) -> denied(stage2Nonce), TERMINAL,
-- keeping the obligation mapping (the transaction stays bound to the denial).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
local rec = cjson.decode(existing)
if rec['state'] == 'denied' then
  if rec['stage2Nonce'] == ARGV[1] then
    return 'denied_same'
  end
  return 'conflict'
end
if (rec['state'] ~= 'issued' and rec['state'] ~= 'completed') or rec['stage2Nonce'] ~= ARGV[1] then
  return 'conflict'
end
rec['state'] = 'denied'
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'denied_new'
LUA;

    /**
     * Atomic rearm: issued(expectedStage2Nonce) -> available (the
     * reservation fields + stage2Nonce cleared, KEEPTTL). A different
     * nonce or any other state is an atomic no-op (false).
     */
    private const REARM_LUA = <<<'LUA'
-- Chain rearm: issued(expectedNonce) -> available (a fresh stage-2 mint).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
local rec = cjson.decode(existing)
if (rec['state'] ~= 'issued' and rec['state'] ~= 'completed') or rec['stage2Nonce'] ~= ARGV[1] then
  return false
end
rec['state'] = 'available'
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
rec['stage2Nonce'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return true
LUA;

    /**
     * Owner-gated release: reserved(me) -> available (the reservation
     * holder's retry path — a refused or failed issuance must not burn
     * the ticket). A NON-owner release is an atomic no-op: a failing
     * request can never free another owner's live reservation. The chain
     * TTL is preserved (KEEPTTL, Redis 6.0+).
     */
    private const RELEASE_LUA = <<<'LUA'
-- Chain release: reserved(owner) -> available, owner-gated.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
local rec = cjson.decode(existing)
if rec['state'] ~= 'reserved' then
  return false
end
if rec['owner'] ~= ARGV[1] then
  return false
end
rec['state'] = 'available'
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return true
LUA;

    /**
     * DEPRECATED legacy completion: reserved(owner) -> completed(
     * stage2Nonce) — the historical name of the terminal-with-nonce
     * state, semantically identical to markIssued() -> issued. The
     * reservation fields are cleared (the completed record keeps its TTL
     * so a retry recovers the issued challenge).
     */
    private const COMPLETE_LUA = <<<'LUA'
-- Chain completion (DEPRECATED legacy): reserved(owner) -> completed(stage2Nonce).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
local rec = cjson.decode(existing)
if rec['state'] ~= 'reserved' then
  return false
end
if rec['owner'] ~= ARGV[1] then
  return false
end
rec['state'] = 'completed'
rec['stage2Nonce'] = ARGV[2]
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return cjson.encode(rec)
LUA;

    /**
     * Compare-delete the obligation mapping only while it still points at
     * this chainId (a re-created chain of the same transaction must never
     * be unlinked by a stale delete).
     */
    private const DELETE_OBLIGATION_LUA = <<<'LUA'
-- Chain obligation compare-delete: only while it still points at this chain.
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('DEL', KEYS[1])
end
return 1
LUA;

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwi',
    ) {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        // The deprecated legacy path is NOT transaction-anchored (it
        // carries no obligation id): the record carries a DERIVED
        // placeholder obligation id (never a real transaction mapping —
        // hash of the random chain id, no obligation key is written), so
        // the strict v2 decode stays satisfied.
        if ($requiredAction === null || !\in_array($requiredAction, self::CHAINABLE_ACTIONS, true)) {
            throw new \InvalidArgumentException('a chainable requiredAction (Sha16..Argon64) is required to create a chain record');
        }
        $requestBinding = $requestBinding !== '' ? $requestBinding : null;
        $this->setWithTtl(
            $this->key($chainId),
            (string) json_encode([
                'v' => 2,
                'stage1Nonce' => $stage1Nonce,
                'scope' => $scope,
                'obligationId' => hash('sha256', $chainId),
                'requiredAction' => $requiredAction,
                'requiredRank' => RiskAction::from($requiredAction)->rank(),
                'policyVersion' => $policyVersion,
                'chainDepth' => 2,
                'state' => 'available',
                'owner' => null,
                'leaseUntil' => null,
                'stage2Nonce' => null,
                'requestBinding' => $requestBinding,
                'expiresAt' => $this->serverTime() + max(1, $ttlSecs),
            ], JSON_THROW_ON_ERROR),
            max(1, $ttlSecs),
        );
    }

    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        if (!\in_array($requiredAction, self::CHAINABLE_ACTIONS, true)) {
            throw new \InvalidArgumentException('a chainable requiredAction (Sha16..Argon64) is required to create a chain record');
        }
        $requestBinding = $requestBinding !== '' ? $requestBinding : null;
        $now = $this->serverTime();
        $ttl = max(1, $ttlSecs);
        $this->setWithTtl(
            $this->key($chainId),
            (string) json_encode([
                'v' => 2,
                'stage1Nonce' => $stage1Nonce,
                'scope' => $scope,
                'obligationId' => $obligationId,
                'requiredAction' => $requiredAction,
                'requiredRank' => RiskAction::from($requiredAction)->rank(),
                'policyVersion' => $policyVersion,
                'chainDepth' => 2,
                'state' => 'available',
                'owner' => null,
                'leaseUntil' => null,
                'stage2Nonce' => null,
                'requestBinding' => $requestBinding,
                'expiresAt' => $now + $ttl,
            ], JSON_THROW_ON_ERROR),
            $ttl,
        );
        $this->setWithTtl($this->obligationKey($obligationId), $chainId, $ttl);
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $chainId = (string) $this->evalScript(self::CREATE_OR_GET_OBLIGATION_LUA, [
            $this->key($chainId),
            $this->obligationKey($obligationId),
        ], [
            $obligationId,
            $chainId,
            $stage1Nonce,
            $scope,
            $requiredAction,
            (string) $requiredRank,
            (string) $policyVersion,
            $requestBinding,
            (string) $expiresAt,
            (string) max(1, $ttlSecs),
            self::key(''),
        ]);

        return $chainId;
    }

    public function obligationChainId(string $obligationId): ?string
    {
        $chainId = $this->redis->get($this->obligationKey($obligationId));
        if (!\is_string($chainId) || $chainId === '') {
            return null;
        }

        return $chainId;
    }

    public function read(string $chainId): ?array
    {
        $raw = $this->redis->get($this->key($chainId));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return self::wire(self::decodeState($raw));
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        $this->assertLiveRecord($chainId);
        $status = $this->evalScript(self::RESERVE_LUA, [$this->key($chainId)], [$ownerToken, (string) max(1, $leaseSecs)]);

        return \is_string($status) && \in_array($status, ['available', 'retry', 'busy', 'taken_over', 'issued', 'verified', 'completed', 'step_up_required', 'denied', 'missing'], true)
            ? $status
            : 'missing';
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $record = $this->read($chainId);
        if ($record === null || $record['state'] !== 'reserved') {
            return;
        }
        $this->evalScript(self::RELEASE_LUA, [$this->key($chainId)], [$ownerToken]);
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        $this->assertLiveRecord($chainId);
        $result = $this->evalScript(self::MARK_ISSUED_LUA, [$this->key($chainId)], [$ownerToken, $stage2Nonce]);

        return \is_string($result) && \in_array($result, ['issued_new', 'issued_same', 'verified_same', 'conflict', 'not_owner', 'missing'], true)
            ? $result
            : 'missing';
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        $record = $this->read($chainId);
        if ($record === null) {
            return 'missing';
        }
        $result = $this->evalScript(self::MARK_VERIFIED_LUA, [
            $this->key($chainId),
            $this->obligationKey((string) $record['obligationId']),
        ], [$stage2Nonce, $chainId]);

        return \is_string($result) && \in_array($result, ['verified_new', 'verified_same', 'conflict', 'missing'], true)
            ? $result
            : 'missing';
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        $this->assertLiveRecord($chainId);
        $result = $this->evalScript(self::MARK_STEP_UP_REQUIRED_LUA, [$this->key($chainId)], [$stage2Nonce]);

        return \is_string($result) && \in_array($result, ['step_up_required_new', 'step_up_required_same', 'conflict', 'missing'], true)
            ? $result
            : 'missing';
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        $this->assertLiveRecord($chainId);
        $result = $this->evalScript(self::MARK_DENIED_LUA, [$this->key($chainId)], [$stage2Nonce]);

        return \is_string($result) && \in_array($result, ['denied_new', 'denied_same', 'conflict', 'missing'], true)
            ? $result
            : 'missing';
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        $this->assertLiveRecord($chainId);
        $rearmed = $this->evalScript(self::REARM_LUA, [$this->key($chainId)], [$expectedStage2Nonce]);

        return $rearmed === true || $rearmed === 1;
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        $this->evalScript(self::DELETE_OBLIGATION_LUA, [$this->obligationKey($obligationId)], [$chainId]);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        $record = $this->read($chainId);
        if ($record === null || $record['state'] !== 'reserved') {
            return null;
        }
        $raw = $this->evalScript(self::COMPLETE_LUA, [$this->key($chainId)], [$ownerToken, $stage2Nonce]);
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return self::wire(self::decodeState($raw));
    }

    /**
     * The strict v2 decode — ALL-OR-NOTHING: a missing/malformed field or
     * a state-invariant violation throws
     * {@see MalformedChainedChallengeStateException} (NEVER defaults: a
     * corrupt requiredAction must never become '', policyVersion never 1,
     * chainDepth never 2, state never available). Validates: schema
     * version 2; the Kiwi base64 nonce shape for BOTH stage-1 and
     * stage-2 nonces; the canonical scope shape; the exact
     * 64-lowercase-hex obligation id; a chainable PoW action
     * (Sha16..Argon64 — never StepUp/Deny); a bounded rank CONSISTENT
     * with the action; a positive policy version; chain depth exactly 2;
     * the exact state enum (the TERMINAL step_up_required/denied states
     * included); owner/leaseUntil REQUIRED in reserved and NULL
     * elsewhere; stage2Nonce REQUIRED with the Kiwi base64 nonce shape in
     * issued/verified/step_up_required/denied (and the legacy completed)
     * and NULL elsewhere; an integer expiry; a well-shaped nullable
     * request binding.
     *
     * @throws MalformedChainedChallengeStateException
     */
    private static function decodeState(string $raw): array
    {
        try {
            $rec = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new MalformedChainedChallengeStateException('chain record is not valid JSON', 0, $e);
        }
        if (!\is_array($rec)) {
            throw new MalformedChainedChallengeStateException('chain record must be a JSON object');
        }

        return self::validateState($rec);
    }

    /** @param array<string, mixed> $rec */
    private static function validateState(array $rec): array
    {
        if (($rec['v'] ?? null) !== 2) {
            throw new MalformedChainedChallengeStateException('chain record schema version must be 2');
        }
        $stage1Nonce = $rec['stage1Nonce'] ?? null;
        if (!\is_string($stage1Nonce) || preg_match(self::NONCE_PATTERN, $stage1Nonce) !== 1) {
            throw new MalformedChainedChallengeStateException('chain record stage1Nonce must be a Kiwi base64 nonce');
        }
        $scope = $rec['scope'] ?? null;
        if (!\is_string($scope) || preg_match(self::IDENTIFIER_PATTERN, $scope) !== 1) {
            throw new MalformedChainedChallengeStateException('chain record scope must match the canonical identifier shape');
        }
        $obligationId = $rec['obligationId'] ?? null;
        if (!\is_string($obligationId) || preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new MalformedChainedChallengeStateException('chain record obligationId must be 64 lowercase hex characters');
        }
        $requiredAction = $rec['requiredAction'] ?? null;
        if (!\is_string($requiredAction) || !\in_array($requiredAction, self::CHAINABLE_ACTIONS, true)) {
            throw new MalformedChainedChallengeStateException('chain record requiredAction must be a chainable PoW action (Sha16..Argon64)');
        }
        $requiredRank = $rec['requiredRank'] ?? null;
        if (!\is_int($requiredRank) || $requiredRank !== RiskAction::from($requiredAction)->rank()) {
            throw new MalformedChainedChallengeStateException('chain record requiredRank must be the rank of the required action');
        }
        $policyVersion = $rec['policyVersion'] ?? null;
        if (!\is_int($policyVersion) || $policyVersion < 1) {
            throw new MalformedChainedChallengeStateException('chain record policyVersion must be a positive integer');
        }
        if (($rec['chainDepth'] ?? null) !== 2) {
            throw new MalformedChainedChallengeStateException('chain record chainDepth must be exactly 2');
        }
        $state = $rec['state'] ?? null;
        if (!\is_string($state) || !\in_array($state, self::STATES, true)) {
            throw new MalformedChainedChallengeStateException('chain record state must be one of available|reserved|issued|verified|step_up_required|denied');
        }
        $owner = $rec['owner'] ?? null;
        $leaseUntil = $rec['leaseUntil'] ?? null;
        if ($state === 'reserved') {
            if (!\is_string($owner) || $owner === '' || !\is_int($leaseUntil)) {
                throw new MalformedChainedChallengeStateException('chain record owner/leaseUntil are required in the reserved state');
            }
        } elseif ($owner !== null || $leaseUntil !== null) {
            throw new MalformedChainedChallengeStateException('chain record owner/leaseUntil must be null outside the reserved state');
        }
        $stage2Nonce = $rec['stage2Nonce'] ?? null;
        if ($state === 'issued' || $state === 'verified' || $state === 'completed' || $state === 'step_up_required' || $state === 'denied') {
            if (!\is_string($stage2Nonce) || preg_match(self::NONCE_PATTERN, $stage2Nonce) !== 1) {
                throw new MalformedChainedChallengeStateException('chain record stage2Nonce must be a Kiwi base64 nonce in the issued/terminal states');
            }
        } elseif ($stage2Nonce !== null) {
            throw new MalformedChainedChallengeStateException('chain record stage2Nonce must be null in the available/reserved states');
        }
        $requestBinding = $rec['requestBinding'] ?? null;
        if ($requestBinding !== null && (!\is_string($requestBinding) || preg_match(self::IDENTIFIER_PATTERN, $requestBinding) !== 1)) {
            throw new MalformedChainedChallengeStateException('chain record requestBinding must match the canonical identifier shape or be null');
        }
        if (!\is_int($rec['expiresAt'] ?? null)) {
            throw new MalformedChainedChallengeStateException('chain record expiresAt must be an integer');
        }

        return $rec;
    }

    /**
     * The wire shape of a strictly-decoded record: the server-held fields
     * with their documented types (owner/leaseUntil/stage2Nonce null when
     * unset).
     *
     * @param array<string, mixed> $rec
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'issued'|'verified'|'step_up_required'|'denied'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int}
     */
    private static function wire(array $rec): array
    {
        return [
            'stage1Nonce' => $rec['stage1Nonce'],
            'scope' => $rec['scope'],
            'requestBinding' => $rec['requestBinding'],
            'requiredAction' => $rec['requiredAction'],
            'requiredRank' => $rec['requiredRank'],
            'policyVersion' => $rec['policyVersion'],
            'chainDepth' => $rec['chainDepth'],
            'state' => $rec['state'],
            'owner' => $rec['owner'],
            'leaseUntil' => $rec['leaseUntil'],
            'stage2Nonce' => $rec['stage2Nonce'],
            'obligationId' => $rec['obligationId'],
            'expiresAt' => $rec['expiresAt'],
        ];
    }

    /**
     * Fail-closed guard before every state transition: the record must
     * EXIST and strictly decode (a corrupt server record is a server
     * anomaly — throw, never transition corrupted state into valid
     * state).
     *
     * @throws MalformedChainedChallengeStateException
     */
    private function assertLiveRecord(string $chainId): void
    {
        $this->read($chainId);
    }

    private function serverTime(): int
    {
        $time = $this->redis->time();
        if (\is_array($time) && isset($time[0])) {
            return (int) $time[0];
        }

        return time();
    }

    private function key(string $chainId): string
    {
        return sprintf('{kiwi:%s}:%s%s', $this->namespace, self::PREFIX, $chainId);
    }

    private function obligationKey(string $obligationId): string
    {
        return sprintf('{kiwi:%s}:%s%s', $this->namespace, self::OBLIGATION_PREFIX, $obligationId);
    }

    /**
     * SET with an EX lifetime in the client-appropriate call shape:
     * phpredis packs the options array, Predis uses the flat form.
     */
    private function setWithTtl(string $key, string $value, int $ttlSecs): void
    {
        if ($this->redis instanceof \Redis) {
            $this->redis->set($key, $value, ['EX' => max(1, $ttlSecs)]);

            return;
        }
        $this->redis->set($key, $value, 'EX', max(1, $ttlSecs));
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
}
