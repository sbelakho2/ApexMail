<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\RedisNamespace;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Storage\ReplicaWaitException;

/**
 * Redis-backed chained-challenge state store implementing the transactional
 * v2 contract: the obligation-anchored Lua state machine (available ->
 * reserved(owner, short lease) -> issued(stage2Nonce)) with terminal
 * verified/step_up_required/denied transitions and obligation-bound
 * nonce-agnostic transaction terminalizations, atomic over one hash-tag
 * key family. Records decode all-or-nothing against the strict v2 schema,
 * see {@see self::decodeState()}: a corrupt record never becomes a
 * defaulted one. The full state machine is documented in
 * docs/chained-challenges.md.
 *
 * Replica durability: with `waitReplicas > 0` every fresh mutating
 * transition is followed by a verified Redis WAIT on the same
 * connection whose acknowledgement count is checked against the
 * threshold. The covered transitions are the chain/obligation creation,
 * the issued transition, the terminal verified / step_up_required /
 * denied transitions, the obligation-bound transaction
 * terminalizations, the obligation removal and the rearm. This matches
 * the fail-closed contract of the core
 * {@see \KiwiCaptcha\Storage\RedisStorage}. Fewer than waitReplicas
 * acknowledged replicas raise {@see ReplicaWaitException}. The caller
 * never learns a success that was not replicated, so a returned
 * Deny/StepUp (or a cleared obligation) is substantially less likely
 * to be lost on a stale-replica promotion. Redis replication remains
 * eventually consistent: the verified WAIT is durability hardening,
 * not a consensus guarantee — acknowledged writes can still be lost
 * under some failover and persistence patterns. A lost terminal
 * transition
 * would let the same logical operation retry against a stale replica
 * and issue or pass. The non-mutating paths (reads, the owner-scoped
 * reservation, the release, idempotent same-state replays and refusals)
 * perform no fresh write and never WAIT. The reservation is a
 * short-lease transient claim, not a terminal state. An idempotent
 * retry can therefore never turn a replica outage into a storage
 * failure. The verified barrier supports the same standalone-connection
 * matrix as the core. A Predis replication aggregate (Sentinel or
 * master-slave), a Predis cluster aggregate and a retry-enabled
 * standalone Predis client are refused at construction with
 * waitReplicas > 0.
 *
 * Authority lane: every Lua transition executes through the guarded
 * {@see \BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor}
 * seam (docs/ha-authority.md). The reservation, the obligation
 * create-or-get, the stage-2 issuance, the terminal verified / step-up
 * / denial / transaction-terminal transitions, the rearm, the release,
 * the completion and the obligation compare-delete are all declared
 * security-final at the call site. The pinned-primary guard therefore
 * re-verifies the authority immediately before each of those writes
 * (zero stale, never inside the verification window). Only the live
 * read rides the ordinary lane.
 */
final class RedisChainedChallengeStateStore implements TransactionalChainedChallengeStateStore
{
    private const PREFIX = 'chain:';

    private const OBLIGATION_PREFIX = 'chain-obligation:';

    /**
     * The encoded primary namespace inside every key this store writes.
     */
    private readonly string $namespace;

    /**
     * The legacy encoded namespace on the digest key version: reads fall
     * back to it (never writes), so the cutover cannot hide an open
     * obligation or chain record. Null on the legacy key version, where
     * the primary namespace already is the legacy segment.
     */
    private readonly ?string $legacyNamespace;

    private readonly RedisSecurityCommandExecutor $lua;

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
     * The canonical v2 wire keys, the only keys a chain record may
     * carry. The strict decode denies every other key (a renamed or
     * extra field fails closed, mirroring the core ChallengeRecord
     * parser's deny-unknown-fields).
     */
    private const WIRE_KEYS = [
        'v', 'stage1Nonce', 'scope', 'obligationId', 'requiredAction', 'requiredRank', 'policyVersion',
        'chainDepth', 'state', 'owner', 'leaseUntil', 'stage2Nonce', 'requestBinding', 'expiresAt',
        'requirementGeneration', 'reservedRequirementGeneration',
    ];

    /**
     * Atomic create-or-get over the chain + obligation keys (same hash
     * tag). No obligation -> create the chain (v2 available) + the
     * obligation (same TTL). The obligation exists -> return the existing
     * chain id, raising the requiredRank/requiredAction when the new
     * reassessment is stronger, never lowering. The obligation points at
     * a missing/corrupt/past-expiry chain -> compare-delete the stale
     * mapping and create the chain fresh (a stale mapping can never block
     * a transaction). The pointed-at chain is a declared key (KEYS[3]),
     * resolved by the caller from a plain read and re-verified inside
     * the script, so no key name is constructed from stored data. A
     * mapping that moved between the read and the script answers
     * 'moved' and the caller retries (bounded, fail-closed on
     * exhaustion). The reply is a three-element table {chainId, mutated,
     * verdict}: `mutated` is 1 exactly when the script performed a write
     * (the fresh creation, the stale-mapping repair or the rank raise).
     * It is 0 when the script only returned the existing chain. The
     * caller applies the verified WAIT durability barrier to the
     * mutating arms only.
     */
    /**
     * The migration-only compare-delete of a stale legacy obligation
     * mapping: one key, one namespace, so it can never span the two hash
     * slots in a single transaction.
     */
    private const DELETE_LEGACY_OBLIGATION_LUA = PersistedJsonLuaPredicate::LUA . <<<'LUA'
-- kiwicaptcha legacy-obligation compare-delete (migration only)
local mapped = redis.call('GET', KEYS[1])
if mapped and mapped == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
LUA;

    private const CREATE_OR_GET_OBLIGATION_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain obligation create-or-get (chain + obligation, one hash tag).
-- EVERY key the script touches is a declared KEYS argument: KEYS[3] is the
-- chain the obligation mapping points at, resolved by the caller from a
-- plain read and RE-VERIFIED inside the script (a mapping that no longer
-- equals the caller's read answers 'moved' and the caller retries), so no
-- key name is ever constructed from stored data — the EVAL contract holds
-- on sharded/proxied/Redis Cloud topologies too.
local now = tonumber(redis.call('TIME')[1])
local mapped = redis.call('GET', KEYS[2])
if mapped then
  if mapped ~= ARGV[11] then
    return {ARGV[11], 0, 'moved'}
  end
  local chained = redis.call('GET', KEYS[3])
  if chained then
    -- The pointed-chain predicate is the SAME authority as READ_LUA:
    -- a key without a lifetime is corrupted state, a non-decodable or
    -- structurally invalid record is corrupted state. Corrupt state is
    -- never healed (zero writes here) — only a genuinely missing or
    -- signed-expired record is a stale mapping eligible for repair. The
    -- caller turns 'corrupt' into the retryable fail-closed 503.
    if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[3]))) then
      return {'', 0, 'corrupt'}
    end
    local rec = decodeUniqueObject(chained)
    if rec == nil or not isValidChainRecord(rec) then
      return {'', 0, 'corrupt'}
    end
    -- The binding invariant: the mapping is not authenticated, so a
    -- corrupted mapping could point this transaction at ANOTHER
    -- transaction's perfectly valid chain. The pointed record must BE
    -- this transaction's chain (obligation id, scope, request binding
    -- and policy epoch all equal), or the state is corrupt with zero
    -- writes — a stronger reassessment must never raise a foreign
    -- chain's requirement.
    local recBinding = rec['requestBinding']
    if recBinding == nil or recBinding == cjson.null then
      recBinding = ''
    end
    if rec['obligationId'] ~= ARGV[1]
      or rec['scope'] ~= ARGV[4]
      or tostring(rec['policyVersion']) ~= ARGV[7]
      or recBinding ~= ARGV[8] then
      return {'', 0, 'corrupt'}
    end
    -- A past-expiry pointed-at record is stale like a missing one: the
    -- create-or-get heals the mapping with a fresh chain, the mirror of
    -- the Array store's expiresAt-vs-clock check.
    if not chainRecordExpired(rec, now) then
      local newRank = tonumber(ARGV[6])
      if newRank > tonumber(rec['requiredRank']) then
        -- A requirement raise is monotonic and bumps the generation.
        rec['requiredRank'] = newRank
        rec['requiredAction'] = ARGV[5]
        if rec['requirementGeneration'] == nil then
          rec['requirementGeneration'] = 1
        end
        rec['requirementGeneration'] = tonumber(rec['requirementGeneration']) + 1
        if rec['state'] == 'issued' or rec['state'] == 'completed' or rec['state'] == 'verified' then
          -- The chain already carries an issued stage-2 challenge. The
          -- old nonce can never be upgraded in place (a weaker challenge
          -- would stay redeemable while the record claims a stronger
          -- requirement), so the chain fails closed to the terminal
          -- step-up state: MARK_VERIFIED accepts only `issued`, the
          -- controller refuses to recover the stale nonce, and the
          -- validator refuses to Pass a stage-2 record that does not
          -- satisfy the current requirement.
          rec['state'] = 'step_up_required'
          rec['owner'] = cjson.null
          rec['leaseUntil'] = cjson.null
          rec['reservedRequirementGeneration'] = cjson.null
        end
        redis.call('SET', KEYS[3], cjson.encode(rec), 'KEEPTTL')
        return {ARGV[11], 1, ''}
      end
      return {ARGV[11], 0, ''}
    end
  end
  -- stale mapping (missing or expired pointed chain): compare-delete +
  -- create fresh in the SAME script.
  if redis.call('GET', KEYS[2]) == ARGV[11] then
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
  expiresAt = tonumber(ARGV[9]),
  requirementGeneration = 1,
  reservedRequirementGeneration = cjson.null
}
if rec['requestBinding'] == '' then
  rec['requestBinding'] = cjson.null
end
local ttl = tonumber(ARGV[10])
redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', ttl)
redis.call('SET', KEYS[2], ARGV[2], 'EX', ttl)
return {ARGV[2], 1, ''}
LUA;

    /**
     * Owner-scoped reservation with a short lease: available ->
     * reserved(me, now + the lease, capped by the remaining TTL). Redis
     * TIME drives the lease; KEEPTTL preserves the record's own remaining
     * TTL, since the signed ticket expiry is the true bound. Reserved by
     * me -> 'retry'; reserved by another owner with a live lease ->
     * 'busy'; expired lease -> takeover ('taken_over').
     * Issued/verified/completed -> 'issued'/'verified'/'completed'. The
     * terminal step_up_required / denied states answer
     * 'step_up_required'/'denied' (the obligation stays bound, never
     * issue). A record without a key lifetime or with a passed signed
     * expiry is stale -> 'missing' (never manufacture a lifetime, never
     * reserve a past-expiry record).
     */
    private const RESERVE_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain reservation: owner-scoped SHORT lease (redis TIME + remaining lifetime).
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- A PRESENT empty value is corrupted state, never absence.
if existing == '' then
  return 'corrupt'
end
-- The PTTL sentinels classify the boundary exactly: -2 is the key
-- actually gone (missing), -1 is a PRESENT record whose lifetime was
-- stripped (corrupt, the same answer every other transition gives), and
-- a sub-second remainder (PTTL 0) is a LIVE key. Manufacturing
-- 'missing' for a persistent record would let a corrupted reservation
-- look like an expired challenge.
local key_pttl_ms = tonumber(redis.call('PTTL', KEYS[1]))
if key_pttl_ms == -2 then
  return 'missing'
end
if chainKeyLifetimeMissing(key_pttl_ms) then
  return 'corrupt'
end
-- The reservation lease never outlives the key lifetime, and a
-- sub-second remainder rounds UP to one second so the bounded SET EX
-- below can never write a non-positive expiry.
local remaining_lease_secs = math.max(1, math.floor(key_pttl_ms / 1000))
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
-- A past-expiry but still-live record is stale: fail closed like the
-- Array mirror's liveRecord() sweep (never reserve an expired ticket).
if chainRecordExpired(rec, now) then
  return 'missing'
end
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
  if remaining_lease_secs < lease then
    lease = remaining_lease_secs
  end
  rec['state'] = 'reserved'
  rec['owner'] = ARGV[1]
  rec['leaseUntil'] = now + lease
  if rec['requirementGeneration'] == nil or rec['requirementGeneration'] == cjson.null then
    rec['requirementGeneration'] = 1
  end
  rec['reservedRequirementGeneration'] = tonumber(rec['requirementGeneration'])
  redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
  return 'taken_over'
end
local lease = tonumber(ARGV[2])
if remaining_lease_secs < lease then
  lease = remaining_lease_secs
end
rec['state'] = 'reserved'
rec['owner'] = ARGV[1]
rec['leaseUntil'] = now + lease
if rec['requirementGeneration'] == nil or rec['requirementGeneration'] == cjson.null then
  rec['requirementGeneration'] = 1
end
rec['reservedRequirementGeneration'] = tonumber(rec['requirementGeneration'])
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'available'
LUA;

    /**
     * Idempotent issuance: reserved(me) -> issued(stage2Nonce), KEEPTTL:
     * a state transition, never a delete, so the issued record lets a
     * retry recover the issued challenge instead of re-minting. Same
     * nonce again -> 'issued_same', verified with the same nonce ->
     * 'verified_same', any other nonce on an issued/completed chain, or
     * any nonce on a terminal step_up_required/denied chain -> 'conflict',
     * a non-owner (or an unreserved chain) -> 'not_owner', absent ->
     * 'missing'. A record without a key lifetime or with a passed signed
     * expiry is stale -> 'missing' (the same fail-closed guards as the
     * reservation).
     */
    private const MARK_ISSUED_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain issuance: reserved(owner) -> issued(stage2Nonce), idempotent.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return 'missing'
end
if rec['state'] == 'reserved' then
  if rec['owner'] ~= ARGV[1] then
    return 'not_owner'
  end
  -- The reservation CAS: the minted challenge was issued against the
  -- requirement generation captured at reservation time. A raise in
  -- between bumped the chain's generation, so the weaker challenge must
  -- never be installed: the caller discards it and retries against the
  -- current requirement. A legacy reservation without the snapshot is
  -- logically generation 1 (never "no fence").
  local reservedGeneration = rec['reservedRequirementGeneration']
  if reservedGeneration == nil or reservedGeneration == cjson.null then
    reservedGeneration = 1
  end
  local currentGeneration = rec['requirementGeneration']
  if currentGeneration == nil or currentGeneration == cjson.null then
    currentGeneration = 1
  end
  if reservedGeneration ~= currentGeneration then
    return 'stale_requirement'
  end
  rec['state'] = 'issued'
  rec['stage2Nonce'] = ARGV[2]
  rec['owner'] = cjson.null
  rec['leaseUntil'] = cjson.null
  rec['reservedRequirementGeneration'] = cjson.null
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
     * Terminal verification: issued(nonce) -> verified(nonce), KEEPTTL,
     * the terminal record kept until its TTL, atomically deleting the
     * obligation mapping (KEYS[2]) only if it still points at this
     * chainId. Same nonce again -> 'verified_same'; a different nonce or
     * a non-issuable state -> 'conflict'; absent -> 'missing'. A record
     * without a key lifetime or with a passed signed expiry is stale ->
     * 'missing' (a past-expiry chain can never verify).
     */
    private const MARK_VERIFIED_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain verification: issued(stage2Nonce) -> verified(stage2Nonce), TERMINAL,
-- deleting the obligation mapping only while it still points at this chain.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return 'missing'
end
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
     * Terminal step-up: issued(nonce) -> step_up_required(nonce), KEEPTTL,
     * the terminal record kept until its TTL. The obligation mapping is
     * kept: the transaction stays bound to the step-up requirement, so a
     * later challenge request for the same transaction re-encounters the
     * terminal state (never a new stage-1). Same nonce again ->
     * 'step_up_required_same'; a different nonce or a non-issuable state
     * -> 'conflict'; absent -> 'missing'. A record without a key lifetime
     * or with a passed signed expiry is stale -> 'missing'.
     */
    private const MARK_STEP_UP_REQUIRED_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain step-up: issued(stage2Nonce) -> step_up_required(stage2Nonce), TERMINAL,
-- keeping the obligation mapping (the transaction stays bound to the step-up).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return 'missing'
end
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
     * Terminal denial: issued(nonce) -> denied(nonce), KEEPTTL, the
     * terminal record kept until its TTL. The obligation mapping is
     * kept: the transaction stays bound to its final denial, so a later
     * challenge request for the same transaction re-encounters the
     * terminal state (never a new stage-1). Same nonce again ->
     * 'denied_same'; a different nonce or a non-issuable state ->
     * 'conflict'; absent -> 'missing'. A record without a key lifetime
     * or with a passed signed expiry is stale -> 'missing'.
     */
    private const MARK_DENIED_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain denial: issued(stage2Nonce) -> denied(stage2Nonce), TERMINAL,
-- keeping the obligation mapping (the transaction stays bound to the denial).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return 'missing'
end
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
     * Obligation-bound, nonce-agnostic transaction terminalization: an
     * open obligation (available|reserved|issued|completed) -> denied,
     * KEEPTTL, the record keeps its own remaining TTL. The transition is
     * atomic over both keys, the chain record + the obligation mapping,
     * one hash tag: the chain record must still agree on the obligation
     * id and the obligation mapping must still point at this chain.
     * Otherwise nothing is transitioned, fail closed, 'obligation_moved',
     * and the caller re-reads the requirement and terminalizes the
     * current chain. The obligation mapping is kept, so the transaction
     * stays bound to its final denial, and the stage2Nonce field is
     * preserved: the exact stage-2 nonce when one exists, null otherwise,
     * so the terminal state carries an optional stage-2 nonce. Results:
     * 'denied_same' (already denied), 'conflict' (the other terminal
     * disposition, a terminal state can never be reopened or flipped),
     * 'already_verified' (defensive, the obligation should already be
     * gone), 'already_completed' (the mapping is gone, the transaction
     * already ended via Pass), absent -> 'missing'.
     */
    private const MARK_TRANSACTION_DENIED_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Transaction denial: OBLIGATION-BOUND NONCE-AGNOSTIC terminal transition of
-- an OPEN obligation (available|reserved|issued|completed -> denied, KEEPTTL —
-- the record keeps its OWN remaining TTL; the obligation mapping is KEPT, the
-- chainId and the original expiry are preserved). The transition is ATOMIC
-- over BOTH keys (one hash tag): the chain record must STILL agree on the
-- obligation id (ARGV[2]) AND the obligation mapping (KEYS[2]) must STILL
-- point at this chain (ARGV[1]) — otherwise the transaction's chain moved and
-- NOTHING is transitioned (fail closed). The stage2Nonce field is PRESERVED
-- (the exact stage-2 nonce when one exists, null otherwise) — the terminal
-- state carries an OPTIONAL stage-2 nonce. RACE SEMANTICS: this transition
-- WINS against an in-flight reservation (the reserve on the terminalized
-- chain answers 'denied') and against an in-flight issuance (a markIssued on
-- the terminalized chain answers 'conflict'); against markVerified the FIRST
-- writer wins (verified -> 'already_completed' — the obligation is already
-- gone; terminal -> markVerified 'conflict').
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
if rec['obligationId'] ~= ARGV[2] then
  return 'obligation_moved'
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return 'missing'
end
local mapped = redis.call('GET', KEYS[2])
if not mapped then
  return 'already_completed'
end
if mapped ~= ARGV[1] then
  return 'obligation_moved'
end
if rec['state'] == 'denied' then
  return 'denied_same'
end
if rec['state'] == 'step_up_required' then
  return 'conflict'
end
if rec['state'] == 'verified' then
  return 'already_verified'
end
if rec['state'] ~= 'available' and rec['state'] ~= 'reserved' and rec['state'] ~= 'issued' and rec['state'] ~= 'completed' then
  return 'conflict'
end
rec['state'] = 'denied'
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
rec['reservedRequirementGeneration'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'denied_new'
LUA;

    /**
     * Obligation-bound, nonce-agnostic transaction terminalization: an
     * open obligation (available|reserved|issued|completed) ->
     * step_up_required, KEEPTTL, the record keeps its own remaining TTL.
     * The transition is atomic over both keys, the chain record + the
     * obligation mapping, one hash tag: the chain record must still
     * agree on the obligation id and the obligation mapping must still
     * point at this chain. Otherwise nothing is transitioned, fail
     * closed, 'obligation_moved', and the caller re-reads the
     * requirement and terminalizes the current chain. The obligation
     * mapping is kept, so the transaction stays bound to the step-up
     * requirement, and the stage2Nonce field is preserved: the exact
     * stage-2 nonce when one exists, null otherwise, so the terminal
     * state carries an optional stage-2 nonce. Results:
     * 'step_up_required_same' (already step_up_required), 'conflict'
     * (the other terminal disposition, a terminal state can never be
     * reopened or flipped), 'already_verified' (defensive, the
     * obligation should already be gone), 'already_completed' (the
     * mapping is gone, the transaction already ended via Pass), absent
     * -> 'missing'.
     */
    private const MARK_TRANSACTION_STEP_UP_REQUIRED_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Transaction step-up: OBLIGATION-BOUND NONCE-AGNOSTIC terminal transition of
-- an OPEN obligation (available|reserved|issued|completed -> step_up_required,
-- KEEPTTL — the record keeps its OWN remaining TTL; the obligation mapping is
-- KEPT, the chainId and the original expiry are preserved). The transition is
-- ATOMIC over BOTH keys (one hash tag): the chain record must STILL agree on
-- the obligation id (ARGV[2]) AND the obligation mapping (KEYS[2]) must STILL
-- point at this chain (ARGV[1]) — otherwise the transaction's chain moved and
-- NOTHING is transitioned (fail closed). The stage2Nonce field is PRESERVED
-- (the exact stage-2 nonce when one exists, null otherwise) — the terminal
-- state carries an OPTIONAL stage-2 nonce. RACE SEMANTICS: this transition
-- WINS against an in-flight reservation (the reserve on the terminalized
-- chain answers 'step_up_required') and against an in-flight issuance (a
-- markIssued on the terminalized chain answers 'conflict'); against
-- markVerified the FIRST writer wins (verified -> 'already_completed' — the
-- obligation is already gone; terminal -> markVerified 'conflict').
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
if rec['obligationId'] ~= ARGV[2] then
  return 'obligation_moved'
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return 'missing'
end
local mapped = redis.call('GET', KEYS[2])
if not mapped then
  return 'already_completed'
end
if mapped ~= ARGV[1] then
  return 'obligation_moved'
end
if rec['state'] == 'step_up_required' then
  return 'step_up_required_same'
end
if rec['state'] == 'denied' then
  return 'conflict'
end
if rec['state'] == 'verified' then
  return 'already_verified'
end
if rec['state'] ~= 'available' and rec['state'] ~= 'reserved' and rec['state'] ~= 'issued' and rec['state'] ~= 'completed' then
  return 'conflict'
end
rec['state'] = 'step_up_required'
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
rec['reservedRequirementGeneration'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'step_up_required_new'
LUA;

    /**
     * Atomic rearm: issued(expectedStage2Nonce) -> available, the
     * reservation fields + stage2Nonce cleared, KEEPTTL. A different
     * nonce or any other state is an atomic no-op (false). A record
     * without a key lifetime or with a passed signed expiry is stale
     * (false), the same fail-closed guards as every other mutation.
     */
    private const REARM_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain rearm: issued(expectedNonce) -> available (a fresh stage-2 mint).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return false
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return false
end
if (rec['state'] ~= 'issued' and rec['state'] ~= 'completed') or rec['stage2Nonce'] ~= ARGV[1] then
  return false
end
rec['state'] = 'available'
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
rec['reservedRequirementGeneration'] = cjson.null
rec['stage2Nonce'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return true
LUA;

    /**
     * Owner-gated release: reserved(me) -> available, the reservation
     * holder's retry path: a refused or failed issuance must not burn
     * the ticket. A non-owner release is an atomic no-op: a failing
     * request can never free another owner's live reservation. A record
     * without a key lifetime or with a passed signed expiry is stale and
     * never released (false), the same fail-closed guards as every other
     * mutation. The chain TTL is preserved (KEEPTTL, Redis 6.0+).
     */
    private const RELEASE_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain release: reserved(owner) -> available, owner-gated.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return false
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return false
end
if rec['state'] ~= 'reserved' then
  return false
end
if rec['owner'] ~= ARGV[1] then
  return false
end
rec['state'] = 'available'
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
rec['reservedRequirementGeneration'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return true
LUA;

    /**
     * Deprecated legacy completion: reserved(owner) -> completed(
     * stage2Nonce), the historical name of the terminal-with-nonce
     * state, semantically identical to markIssued() -> issued. The
     * reservation fields are cleared (the completed record keeps its TTL
     * so a retry recovers the issued challenge). A record without a key
     * lifetime or with a passed signed expiry is stale (false, the
     * fail-closed guards shared with every mutation).
     */
    private const COMPLETE_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain completion (DEPRECATED legacy): reserved(owner) -> completed(stage2Nonce).
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and every
-- mutating transition fails closed like the reservation does.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return false
end
-- The signed-expiry guard: an expired-but-live record is stale, never
-- transitioned (the Array mirror sweeps it at the same boundary).
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return false
end
if rec['state'] ~= 'reserved' then
  return false
end
if rec['owner'] ~= ARGV[1] then
  return false
end
-- The same reservation CAS as markIssued: a raise between the
-- reservation and the completion bumped the generation, so a weaker
-- challenge is never completed; a legacy reservation without the
-- snapshot is logically generation 1.
local reservedGeneration = rec['reservedRequirementGeneration']
if reservedGeneration == nil or reservedGeneration == cjson.null then
  reservedGeneration = 1
end
local currentGeneration = rec['requirementGeneration']
if currentGeneration == nil or currentGeneration == cjson.null then
  currentGeneration = 1
end
if reservedGeneration ~= currentGeneration then
  return false
end
rec['state'] = 'completed'
rec['stage2Nonce'] = ARGV[2]
rec['owner'] = cjson.null
rec['leaseUntil'] = cjson.null
rec['reservedRequirementGeneration'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return cjson.encode(rec)
LUA;

    /**
     * Compare-delete the obligation mapping only while it still points at
     * this chainId (a re-created chain of the same transaction must never
     * be unlinked by a stale delete). Returns 1 when the mapping was
     * deleted (a fresh mutation), 0 when it did not point at this chain —
     * the caller applies the verified WAIT durability barrier to the
     * deletion only.
     */
    private const DELETE_OBLIGATION_LUA = PersistedJsonLuaPredicate::LUA . <<<'LUA'
-- Chain obligation compare-delete: only while it still points at this chain.
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
LUA;

    /**
     * The live read, one round trip: the record must exist, carry a key
     * lifetime, strictly decode and hold a not-yet-passed signed expiry.
     * Missing or stale (a TTL-less key, an expired-but-live record) ->
     * false (the caller answers null). Corrupt -> 'corrupt' (the caller
     * throws the strict decode exception). Live -> the raw JSON, which
     * the caller re-decodes through the strict PHP validator as the
     * second gate. This is the fail-closed mirror of the Array store's
     * liveRecord(): the read refuses an expired-but-live record and the
     * assertLiveRecord() pre-guard of every transition never lets a
     * stale record reach a mutation.
     */
    private const READ_LUA = PersistedJsonLuaPredicate::LUA . ChainV2LuaPredicate::LUA . <<<'LUA'
-- Chain live read: existence + key lifetime + strict decode + signed expiry.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
-- A PRESENT empty value is corruption, never absence.
if existing == '' then
  return 'corrupt'
end
-- The key-lifetime guard: a TTL-less chain is corrupted state and fails
-- closed at the read like everywhere else.
if chainKeyLifetimeMissing(tonumber(redis.call('PTTL', KEYS[1]))) then
  return 'corrupt'
end
local rec = decodeUniqueObject(existing)
if rec == nil or not isValidChainRecord(rec) then
  return 'corrupt'
end
-- The signed-expiry guard: an expired-but-live record reads as absent,
-- the mirror of the Array store's liveRecord() sweep.
if chainRecordExpired(rec, tonumber(redis.call('TIME')[1])) then
  return false
end
return existing
LUA;

    /**
     * @param \Predis\Client|\Redis $redis         the Redis client shared with
     *                                             the risk state.
     * @param string                $namespace     the risk namespace (the
     *                                             hash-tag discriminator).
     * @param int                   $waitReplicas  when > 0, every fresh
     *                                             mutating transition is
     *                                             followed by a Redis WAIT
     *                                             whose acknowledgement count
     *                                             is verified. The covered
     *                                             transitions are the
     *                                             chain/obligation creation,
     *                                             the issued transition, the
     *                                             terminal verified /
     *                                             step_up_required / denied
     *                                             transitions, the obligation
     *                                             removal and the rearm.
     *                                             Fewer than waitReplicas
     *                                             acked replicas raise
     *                                             {@see ReplicaWaitException}.
     *                                             This is fail-closed: the
     *                                             caller never learns a
     *                                             success that was not
     *                                             replicated. The non-mutating
     *                                             paths (reads, reservations,
     *                                             releases, same-state
     *                                             replays, refusals) never
     *                                             WAIT. Supported on
     *                                             standalone Redis connections
     *                                             only, the same matrix as the
     *                                             core RedisStorage.
     * @param int                   $waitTimeoutMs WAIT timeout in ms (default
     *                                             100).
     */
    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        string $namespace = 'kiwi',
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
        int $namespaceKeyVersion = RedisNamespace::VERSION_LEGACY,
        /**
         * Whether the digest rollout also consults the legacy segment
         * for obligations and chain records (the drained migration's
         * safety net). A fresh install passes false: it has no
         * pre-cutover state, so an unrelated deployment's colliding
         * legacy keys must never surface as its own obligations.
         */
        private readonly bool $readLegacyFallback = true,
    ) {
        // The store receives the RAW configured discriminator and derives
        // the encoded {kiwi:<ns>} tag through the one shared derivation.
        // On the digest key version it also holds the legacy segment: the
        // obligation and chain reads fall back to it, so an open
        // obligation written before the cutover is never invisible and a
        // ticketless request can never downgrade to a fresh stage 1.
        $this->namespace = RedisNamespace::deriveOr($namespace, 'kiwi', $namespaceKeyVersion);
        $this->legacyNamespace = $readLegacyFallback && $namespaceKeyVersion === RedisNamespace::VERSION_DIGEST
            ? RedisNamespace::deriveOr($namespace, 'kiwi', RedisNamespace::VERSION_LEGACY)
            : null;
        $this->refuseVerifiedWaitOnUnsupportedPredisClients();
        $this->lua = new RedisSecurityCommandExecutor($redis);
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        // The deprecated legacy path is not transaction-anchored, it
        // carries no obligation id: the record carries a derived
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
                'requirementGeneration' => 1,
                'reservedRequirementGeneration' => null,
            ], JSON_THROW_ON_ERROR),
            max(1, $ttlSecs),
        );
        // Durability barrier: the fresh chain-state write must reach the
        // configured replica count before the caller hands out a ticket,
        // or a promoted stale replica could re-open the transaction at
        // stage 1.
        if ($this->waitReplicas > 0) {
            $this->waitAndVerify('the chain-state creation');
        }
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
        $ttl = max(1, $ttlSecs);
        // The chain + obligation writes ride the atomic create-or-get Lua:
        // one script, both keys in the same hash tag, executed by Redis as
        // a single unit. The old two-write seam (the chain SET, then the
        // obligation SET) could orphan the chain between the writes —
        // present, yet unreachable through its obligation and uncleanable.
        // An interruption before the script leaves neither key; a lost
        // reply after it leaves both, mutually consistent. The WAIT
        // barrier and the TTL behavior are the create-or-get ones: the
        // fresh creation always mutates (so the barrier always runs on
        // it) and writes both keys with the same EX lifetime.
        $this->createOrGetObligation(
            $obligationId,
            $chainId,
            $stage1Nonce,
            $scope,
            $requestBinding ?? '',
            $requiredAction,
            RiskAction::from($requiredAction)->rank(),
            $policyVersion,
            $this->serverTime() + $ttl,
            $ttl,
        );
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $chainKey = $this->key($chainId);
        $obligationKey = $this->obligationKey($obligationId);

        // Migration provenance: a live obligation written before the
        // namespace cutover must never be shadowed by a fresh primary
        // one. The legacy chain is read (and validated) here; when its
        // requirement is not weaker than the requested one it is
        // returned untouched, and a stronger reassessment fails closed
        // explicitly instead of creating a competing primary chain. Only
        // a stale legacy mapping (dead, expired or corrupt record) is
        // compare-deleted, so the primary create can never be blocked by
        // a dead pointer — and no write ever spans the two namespaces in
        // one transaction.
        $lookup = $this->obligationLookup($obligationId);
        if ($lookup !== null && $lookup['namespace'] === 'legacy') {
            $legacyRequirement = $this->legacyRequirementOrNull($lookup['chainId']);
            if ($legacyRequirement !== null) {
                // The same binding invariant on the migration branch: a
                // corrupted legacy mapping must never make this
                // transaction adopt (or raise) a foreign chain.
                $legacyBinding = $legacyRequirement['requestBinding'] ?? '';
                if (($legacyRequirement['obligationId'] ?? null) !== $obligationId
                    || ($legacyRequirement['scope'] ?? null) !== $scope
                    || (string) $legacyBinding !== $requestBinding
                    || (int) ($legacyRequirement['policyVersion'] ?? 0) !== $policyVersion
                ) {
                    throw new MalformedChainedChallengeStateException('the legacy obligation mapping resolves a chain that belongs to a different transaction');
                }
                if ($requiredRank <= (int) $legacyRequirement['requiredRank']) {
                    return $lookup['chainId'];
                }
                throw new \RuntimeException('the open obligation predates the namespace cutover: a stronger reassessment cannot be applied to the legacy chain (drain the legacy state before raising the requirement)');
            }
            $this->deleteLegacyObligationIfUnchanged($obligationId, $lookup['chainId']);
        }

        // The pointed-at chain is resolved from a plain read and passed as
        // a declared key; a concurrent create-or-get that moved the
        // mapping between the read and the script answers 'moved' and the
        // loop re-reads and retries (bounded, then fail-closed — a
        // silently wrong chain must never be returned).
        for ($attempt = 0; $attempt < 3; ++$attempt) {
            // The lenient mapping read (not the validating
            // obligationChainId): the repair below must see a stale
            // mapping's pointed-at chain id so the script can compare it
            // against its own read and heal the missing/expired corner.
            $read = $this->obligationLookup($obligationId);
            $existing = $read['chainId'] ?? null;
            $reply = $this->lua->executeSecurityFinal(self::CREATE_OR_GET_OBLIGATION_LUA, [
                $chainKey,
                $obligationKey,
                $this->key($existing ?? $chainId),
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
                $existing ?? $chainId,
            ]);
            // The script answers {chainId, mutated, verdict}: `mutated` is
            // 1 exactly when it performed a write (the fresh creation, the
            // stale-mapping repair or the rank raise), 0 when it only
            // returned the existing chain, and `verdict` is 'moved' when
            // the mapping changed between the caller's read and the
            // script. Lua tables are 1-indexed; normalize before
            // destructuring.
            $parts = \is_array($reply) ? array_values($reply) : [];
            if ((string) ($parts[2] ?? '') === 'corrupt') {
                // The pointed-at chain is corrupt state (a non-decodable
                // record, a structural violation, or a stripped key
                // lifetime). Corrupt state is never healed and the
                // mapping is never touched: the caller turns this into
                // the retryable fail-closed path. Only a missing or
                // genuinely expired record repairs the mapping.
                throw new MalformedChainedChallengeStateException('the pointed-at chain record is malformed at the obligation boundary');
            }
            if ((string) ($parts[2] ?? '') !== 'moved') {
                $resolved = \is_string($parts[0] ?? null) ? $parts[0] : $chainId;
                $mutated = (int) ($parts[1] ?? 0) === 1;

                // Durability barrier: the verified WAIT runs only when the
                // script actually wrote (fresh creation / stale-mapping
                // repair / rank raise). A pure recovery of the existing
                // chain performed no write, so no WAIT is issued: an
                // idempotent retry must never turn a replica outage into
                // a storage failure.
                if ($this->waitReplicas > 0 && $mutated) {
                    $this->waitAndVerify('the obligation create-or-get');
                }

                return $resolved;
            }
        }

        throw new \RuntimeException('the obligation create-or-get could not converge: the mapping kept moving');
    }

    public function obligationChainId(string $obligationId): ?string
    {
        $lookup = $this->obligationLookup($obligationId);
        if ($lookup === null) {
            return null;
        }
        // The validating mirror of the Array store's obligationChainId():
        // the pointed-at chain record must strictly decode and be live —
        // a corrupt record (a stripped key lifetime included) fails
        // closed with MalformedChainedChallengeStateException and the
        // mapping is never silently followed to corrupt state, while a
        // missing or signed-expired record is the stale mapping answered
        // null (the create-or-get repairs it; this read never mutates it).
        return $this->read($lookup['chainId']) === null ? null : $lookup['chainId'];
    }

    /**
     * The obligation mapping with its provenance — the lenient read: the
     * chain id plus the namespace it was read from ('primary' or
     * 'legacy'), or null when no mapping exists, without validating the
     * pointed-at chain record. Readers that want the validated answer
     * (null on a stale mapping, fail-closed on a corrupt one) use
     * {@see obligationChainId()}. The writers (the create-or-get retry
     * loop and the migration branch) and the provenance probes consult
     * this read, so a stale mapping can be repaired and a live legacy
     * obligation can never be shadowed by a fresh primary one.
     *
     * @return array{chainId: string, namespace: 'primary'|'legacy'}|null
     */
    public function obligationLookup(string $obligationId): ?array
    {
        $chainId = $this->redis->get($this->obligationKey($obligationId));
        if ($chainId === '') {
            // A present empty mapping is damaged state, never "no open
            // obligation": healing it would restart the transaction.
            throw new MalformedChainedChallengeStateException('the obligation mapping is an empty value');
        }
        if (\is_string($chainId)) {
            if (!ChainId::isValid($chainId)) {
                throw new MalformedChainedChallengeStateException('the obligation mapping carries a malformed chain id');
            }

            return ['chainId' => $chainId, 'namespace' => 'primary'];
        }
        if ($this->legacyNamespace === null) {
            return null;
        }
        // Migration read: the obligation mapping written before the
        // namespace cutover. Reads never migrate the mapping — a
        // transition on the legacy record fails closed in the caller
        // (the primary-namespace scripts answer missing), which never
        // restarts the transaction at stage 1.
        $legacy = $this->redis->get($this->legacyObligationKey($obligationId));
        if ($legacy === '') {
            throw new MalformedChainedChallengeStateException('the legacy obligation mapping is an empty value');
        }
        if (\is_string($legacy)) {
            if (!ChainId::isValid($legacy)) {
                throw new MalformedChainedChallengeStateException('the legacy obligation mapping carries a malformed chain id');
            }

            return ['chainId' => $legacy, 'namespace' => 'legacy'];
        }

        return null;
    }

    /**
     * The live read of a chain record. Absent or stale records answer
     * null: a key without a lifetime, or a record whose signed expiry
     * lapsed while the key is still live. A corrupt record throws the
     * strict v2 decode (fail closed: a corrupt server record can never
     * be transitioned into valid state). The checks run atomically in
     * one Lua script against the Redis clock, the mirror of the Array
     * store's liveRecord().
     */
    public function read(string $chainId): ?array
    {
        $raw = $this->lua->executeRead(self::READ_LUA, [$this->key($chainId)], []);
        if ($raw === false || $raw === null) {
            if ($this->legacyNamespace === null) {
                return null;
            }
            // Migration read: a chain record written before the namespace
            // cutover. The strict decode below still applies, so a
            // corrupt legacy record fails closed exactly like a primary
            // one. Writes stay on the primary namespace; a transition on
            // a legacy-only record fails closed in the caller.
            $raw = $this->lua->executeRead(self::READ_LUA, [$this->legacyKey($chainId)], []);
            if ($raw === false || $raw === null) {
                return null;
            }
        }
        if ($raw === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the read boundary');
        }
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return self::wire(self::decodeState($raw));
    }

    /**
     * The live legacy chain record for the migration branch, or null when
     * the pointed-at record is genuinely missing or expired — states a
     * stale mapping may heal. Corruption is NOT converted to null: the
     * strict decode's MalformedChainedChallengeStateException propagates,
     * the legacy obligation mapping is left untouched, and the caller
     * fails closed. A retained legacy denial whose record was corrupted
     * can therefore never be erased and replaced by a fresh chain.
     *
     * @return array<string, mixed>|null
     */
    private function legacyRequirementOrNull(string $chainId): ?array
    {
        return $this->read($chainId);
    }

    /**
     * Compare-delete a stale legacy obligation mapping (the record it
     * pointed at is dead, expired or corrupt). One key, one namespace:
     * the migration never spans the two hash slots in one transaction,
     * and a mapping that moved since the read is left alone.
     */
    private function deleteLegacyObligationIfUnchanged(string $obligationId, string $expectedChainId): void
    {
        $deleted = (int) $this->lua->executeSecurityFinal(
            self::DELETE_LEGACY_OBLIGATION_LUA,
            [$this->legacyObligationKey($obligationId)],
            [$expectedChainId],
        );
        if ($deleted === 1 && $this->waitReplicas > 0) {
            $this->waitAndVerify('the stale legacy obligation cleanup');
        }
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        $this->assertLiveRecord($chainId);
        $status = $this->lua->executeSecurityFinal(self::RESERVE_LUA, [$this->key($chainId)], [$ownerToken, (string) max(1, $leaseSecs)]);

        if ($status === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the reservation boundary');
        }

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
        $this->lua->executeSecurityFinal(self::RELEASE_LUA, [$this->key($chainId)], [$ownerToken]);
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        $this->assertLiveRecord($chainId);
        // The stage-2 nonce write boundary validates the canonical Kiwi
        // base64 shape (the same pattern the strict decode enforces on
        // stored records, and the same discipline as the obligation-id
        // pattern check): a malformed nonce is refused deterministically
        // instead of being pinned into the record and bricking it on
        // every later read.
        if (preg_match(self::NONCE_PATTERN, $stage2Nonce) !== 1) {
            throw new \InvalidArgumentException('stage2Nonce must be a Kiwi base64 nonce');
        }
        $result = $this->lua->executeSecurityFinal(self::MARK_ISSUED_LUA, [$this->key($chainId)], [$ownerToken, $stage2Nonce]);
        if ($result === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the issuance boundary');
        }
        $status = \is_string($result) && \in_array($result, ['issued_new', 'issued_same', 'verified_same', 'conflict', 'not_owner', 'missing', 'stale_requirement'], true)
            ? $result
            : 'missing';

        // Durability barrier: the fresh reserved -> issued transition must
        // reach the configured replica count before the caller hands the
        // stage-2 challenge out, or a promoted stale replica could re-mint
        // the chain. Same-state replays and refusals performed no write
        // and never WAIT.
        if ($this->waitReplicas > 0 && $status === 'issued_new') {
            $this->waitAndVerify('the issued transition');
        }

        return $status;
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        $record = $this->read($chainId);
        if ($record === null) {
            return 'missing';
        }
        $result = $this->lua->executeSecurityFinal(self::MARK_VERIFIED_LUA, [
            $this->key($chainId),
            $this->obligationKey((string) $record['obligationId']),
        ], [$stage2Nonce, $chainId]);
        if ($result === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the verification boundary');
        }
        $status = \is_string($result) && \in_array($result, ['verified_new', 'verified_same', 'conflict', 'missing'], true)
            ? $result
            : 'missing';

        // Durability barrier: the fresh terminal issued -> verified write
        // (and its atomic obligation deletion) must reach the configured
        // replica count before the caller reports the chain ended, or a
        // promoted stale replica could resurrect the open obligation.
        // Same-state replays and refusals performed no write and never
        // WAIT.
        if ($this->waitReplicas > 0 && $status === 'verified_new') {
            $this->waitAndVerify('the verified transition');
        }

        return $status;
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        $this->assertLiveRecord($chainId);
        $result = $this->lua->executeSecurityFinal(self::MARK_STEP_UP_REQUIRED_LUA, [$this->key($chainId)], [$stage2Nonce]);
        if ($result === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the step-up boundary');
        }
        $status = \is_string($result) && \in_array($result, ['step_up_required_new', 'step_up_required_same', 'conflict', 'missing'], true)
            ? $result
            : 'missing';

        // Durability barrier: the fresh terminal issued ->
        // step_up_required write must reach the configured replica count
        // before the caller reports the step-up, or a promoted stale
        // replica could re-issue the chain — a returned StepUp must never
        // silently become issuable. Same-state replays and refusals
        // performed no write and never WAIT.
        if ($this->waitReplicas > 0 && $status === 'step_up_required_new') {
            $this->waitAndVerify('the step-up-required transition');
        }

        return $status;
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        $this->assertLiveRecord($chainId);
        $result = $this->lua->executeSecurityFinal(self::MARK_DENIED_LUA, [$this->key($chainId)], [$stage2Nonce]);
        if ($result === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the denial boundary');
        }
        $status = \is_string($result) && \in_array($result, ['denied_new', 'denied_same', 'conflict', 'missing'], true)
            ? $result
            : 'missing';

        // Durability barrier: the fresh terminal issued -> denied write
        // must reach the configured replica count before the caller
        // reports the denial, or a promoted stale replica could re-issue
        // the chain — a returned Deny must never silently become
        // issuable. Same-state replays and refusals performed no write
        // and never WAIT.
        if ($this->waitReplicas > 0 && $status === 'denied_new') {
            $this->waitAndVerify('the denied transition');
        }

        return $status;
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $this->assertLiveRecord($chainId);
        $result = $this->lua->executeSecurityFinal(self::MARK_TRANSACTION_DENIED_LUA, [
            $this->key($chainId),
            $this->obligationKey($obligationId),
        ], [$chainId, $obligationId]);
        if ($result === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the transaction-denial boundary');
        }
        $status = \is_string($result) && \in_array($result, ['denied_new', 'denied_same', 'conflict', 'already_verified', 'already_completed', 'obligation_moved', 'missing'], true)
            ? $result
            : 'missing';

        // Durability barrier: the fresh obligation-bound transaction
        // terminalization (open obligation -> denied) must reach the
        // configured replica count before the caller reports the denial,
        // or a promoted stale replica could re-open the transaction. The
        // idempotent same-state replay and the refusals performed no
        // write and never WAIT.
        if ($this->waitReplicas > 0 && $status === 'denied_new') {
            $this->waitAndVerify('the transaction denial terminalization');
        }

        return $status;
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $this->assertLiveRecord($chainId);
        $result = $this->lua->executeSecurityFinal(self::MARK_TRANSACTION_STEP_UP_REQUIRED_LUA, [
            $this->key($chainId),
            $this->obligationKey($obligationId),
        ], [$chainId, $obligationId]);
        if ($result === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the transaction-step-up boundary');
        }
        $status = \is_string($result) && \in_array($result, ['step_up_required_new', 'step_up_required_same', 'conflict', 'already_verified', 'already_completed', 'obligation_moved', 'missing'], true)
            ? $result
            : 'missing';

        // Durability barrier: the fresh obligation-bound transaction
        // terminalization (open obligation -> step_up_required) must
        // reach the configured replica count before the caller reports
        // the step-up, or a promoted stale replica could re-open the
        // transaction. The idempotent same-state replay and the refusals
        // performed no write and never WAIT.
        if ($this->waitReplicas > 0 && $status === 'step_up_required_new') {
            $this->waitAndVerify('the transaction step-up terminalization');
        }

        return $status;
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        $this->assertLiveRecord($chainId);
        $rearmed = $this->lua->executeSecurityFinal(self::REARM_LUA, [$this->key($chainId)], [$expectedStage2Nonce]);
        if ($rearmed === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the rearm boundary');
        }
        $success = $rearmed === true || $rearmed === 1;

        // Durability barrier: the fresh issued -> available rearm must
        // reach the configured replica count before the caller mints a
        // fresh stage-2 challenge, or a promoted stale replica could
        // resurrect the rearmed chain as issued. A refused rearm is an
        // atomic no-op and never WAITs.
        if ($this->waitReplicas > 0 && $success) {
            $this->waitAndVerify('the chain rearm');
        }

        return $success;
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        $deleted = $this->lua->executeSecurityFinal(self::DELETE_OBLIGATION_LUA, [$this->obligationKey($obligationId)], [$chainId]);

        // Durability barrier: the fresh obligation deletion must reach
        // the configured replica count before the caller treats the
        // transaction as ended, or a promoted stale replica could
        // resurrect the obligation and re-open the transaction. A
        // compare-delete that did not point at this chain is an atomic
        // no-op and never WAITs.
        if ($this->waitReplicas > 0 && ($deleted === true || $deleted === 1)) {
            $this->waitAndVerify('the obligation deletion');
        }
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        $record = $this->read($chainId);
        if ($record === null || $record['state'] !== 'reserved') {
            return null;
        }
        // The stage-2 nonce write boundary validates the canonical Kiwi
        // base64 shape like markIssued(): a malformed nonce is refused
        // deterministically instead of being pinned into the record.
        if (preg_match(self::NONCE_PATTERN, $stage2Nonce) !== 1) {
            throw new \InvalidArgumentException('stage2Nonce must be a Kiwi base64 nonce');
        }
        $raw = $this->lua->executeSecurityFinal(self::COMPLETE_LUA, [$this->key($chainId)], [$ownerToken, $stage2Nonce]);
        if ($raw === 'corrupt') {
            throw new MalformedChainedChallengeStateException('the chain record is malformed at the completion boundary');
        }
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $completed = self::wire(self::decodeState($raw));

        // Durability barrier: the deprecated legacy completion is the
        // historical name of the issued transition — the fresh
        // reserved -> completed write must reach the configured replica
        // count before the caller hands the challenge out, the same
        // contract as markIssued(). A refused completion (non-owner /
        // non-reserved) is an atomic no-op and never WAITs.
        if ($this->waitReplicas > 0) {
            $this->waitAndVerify('the chain completion');
        }

        return $completed;
    }

    /**
     * The strict v2 decode, all-or-nothing: a missing/malformed field or
     * a state-invariant violation throws
     * {@see MalformedChainedChallengeStateException}, never defaults: a
     * corrupt requiredAction must never become '', policyVersion never 1,
     * chainDepth never 2, state never available. The same decode runs on
     * the in-memory store, so Array and Redis observe one machine.
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
        // Deny unknown fields, mirroring the core ChallengeRecord::fromArray
        // strictness: a renamed or extra key (e.g. a requestBinding spelled
        // differently) is a corrupt or foreign record and fails closed —
        // the strict decode must never silently drop a field the wire()
        // shape does not know (an undefined-key read would also surface a
        // warning on the real-Redis lane's failOnWarning).
        foreach (array_keys($rec) as $key) {
            if (!\in_array($key, self::WIRE_KEYS, true)) {
                throw new MalformedChainedChallengeStateException(sprintf('chain record carries the unknown key "%s"', $key));
            }
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
        // The monotonic requirement generation: every raise increments it,
        // and a reservation records the generation it was taken against.
        // The field absent is the legacy shape (logical generation 1); an
        // explicit null is corrupt (the canonical writer never emits it).
        if (!\array_key_exists('requirementGeneration', $rec)) {
            $requirementGeneration = 1;
        } else {
            $requirementGeneration = $rec['requirementGeneration'];
            if (!\is_int($requirementGeneration) || $requirementGeneration < 1) {
                throw new MalformedChainedChallengeStateException('chain record requirementGeneration must be a positive integer');
            }
        }
        $state = $rec['state'] ?? null;
        if (!\is_string($state) || !\in_array($state, self::STATES, true)) {
            throw new MalformedChainedChallengeStateException('chain record state must be one of available|reserved|issued|verified|step_up_required|denied');
        }
        $owner = $rec['owner'] ?? null;
        $leaseUntil = $rec['leaseUntil'] ?? null;
        $hasReservedGeneration = \array_key_exists('reservedRequirementGeneration', $rec);
        $reservedGeneration = $rec['reservedRequirementGeneration'] ?? null;
        if ($hasReservedGeneration && $reservedGeneration !== null
            && (!\is_int($reservedGeneration) || $reservedGeneration < 1)) {
            throw new MalformedChainedChallengeStateException('chain record reservedRequirementGeneration must be a positive integer when present');
        }
        if ($state === 'reserved') {
            if (!\is_string($owner) || $owner === '' || !\is_int($leaseUntil)) {
                throw new MalformedChainedChallengeStateException('chain record owner/leaseUntil are required in the reserved state');
            }
            if ($hasReservedGeneration && $reservedGeneration === null) {
                throw new MalformedChainedChallengeStateException('chain record reservedRequirementGeneration must not be null in the reserved state');
            }
        } elseif ($owner !== null || $leaseUntil !== null) {
            throw new MalformedChainedChallengeStateException('chain record owner/leaseUntil must be null outside the reserved state');
        } elseif ($reservedGeneration !== null) {
            throw new MalformedChainedChallengeStateException('chain record reservedRequirementGeneration must be null outside the reserved state');
        }
        $stage2Nonce = $rec['stage2Nonce'] ?? null;
        if ($state === 'issued' || $state === 'verified' || $state === 'completed') {
            if (!\is_string($stage2Nonce) || preg_match(self::NONCE_PATTERN, $stage2Nonce) !== 1) {
                throw new MalformedChainedChallengeStateException('chain record stage2Nonce must be a Kiwi base64 nonce in the issued/verified states');
            }
        } elseif ($state === 'step_up_required' || $state === 'denied') {
            // The terminal states carry an optional stage-2 nonce: the
            // exact stage-2 nonce when the chain was issued before the
            // terminal transition, null when the transaction was
            // terminalized without the exact stage-2 nonce (the
            // nonce-agnostic markTransactionDenied() /
            // markTransactionStepUpRequired() terminalizations of an
            // open obligation). A non-null value must still be a valid
            // Kiwi nonce.
            if ($stage2Nonce !== null && (!\is_string($stage2Nonce) || preg_match(self::NONCE_PATTERN, $stage2Nonce) !== 1)) {
                throw new MalformedChainedChallengeStateException('chain record stage2Nonce must be a Kiwi base64 nonce or null in the terminal step_up_required/denied states');
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
            'requirementGeneration' => $rec['requirementGeneration'] ?? 1,
            'reservedRequirementGeneration' => $rec['reservedRequirementGeneration']
                ?? ($rec['state'] === 'reserved' ? 1 : null),
        ];
    }

    /**
     * Fail-closed guard before every state transition: the record must
     * exist, carry a key lifetime and a not-yet-passed signed expiry,
     * and strictly decode. A corrupt server record is a server anomaly
     * and throws, so corrupted state is never transitioned into valid
     * state; a stale record reads as absent and the transition scripts
     * answer missing/false.
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

    private function legacyKey(string $chainId): string
    {
        return sprintf('{kiwi:%s}:%s%s', $this->legacyNamespace, self::PREFIX, $chainId);
    }

    private function legacyObligationKey(string $obligationId): string
    {
        return sprintf('{kiwi:%s}:%s%s', $this->legacyNamespace, self::OBLIGATION_PREFIX, $obligationId);
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
     * Block until at least waitReplicas replicas acknowledged the previous
     * write, and fail closed when they did not.
     *
     * Redis WAIT returns the number of replicas that processed the write
     * (0 on a replica-less server). The barrier asserts that number
     * against the configured threshold, the same fail-closed check as the
     * core RedisStorage. With `waitReplicas > 0` the durability promise
     * is unconditional. A lagging or unreachable replica set raises
     * {@see ReplicaWaitException} instead of silently downgrading the
     * guarantee. The WAIT runs on the same connection that performed the
     * mutation, so the acknowledgement count is about that write's
     * replication.
     */
    private function waitAndVerify(string $what): void
    {
        if ($this->redis instanceof \Redis) {
            // phpredis has no typed wait method; rawCommand sends the
            // command directly.
            $acked = $this->redis->rawCommand('WAIT', $this->waitReplicas, $this->waitTimeoutMs);
        } else {
            // Predis removed the typed wait() method from its command
            // profile; executeRaw is the raw-command escape hatch (the same
            // semantics as phpredis rawCommand).
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
     * dispatch can hide or re-execute the durability-critical write: the
     * same refusal the core RedisStorage applies.
     *
     * WAIT is connection-relative: it counts replicas of the connection
     * it is sent on and carries no key. A Predis replication aggregate
     * (Sentinel or master-slave) wraps every command in failure-retry
     * logic that can re-execute the WAIT on a replacement connection
     * whose write offset is zero, so the acknowledgement would prove
     * nothing about the original write's replication. A Redis cluster
     * aggregate cannot route a keyless raw WAIT by slot. A retry-enabled
     * standalone Predis client can transparently re-execute the Lua
     * mutation after a lost response, so the returned result may describe
     * the second invocation rather than the one that mutated. Supported
     * topology is standalone Redis only; keep waitReplicas = 0 on an
     * aggregate or a retry-enabled standalone client.
     */
    public function establishReplicationFence(string $what): void
    {
        if ($this->waitReplicas <= 0) {
            return;
        }
        // The same-namespace fence key as the other stores: the chain
        // store has no keyPrefix property, its keying model is the
        // constructor namespace + the chain/obligation key helpers.
        $fenceKey = sprintf('{kiwi:%s}:replication-fence', $this->namespace);
        $token = bin2hex(random_bytes(16));
        if ($this->redis instanceof \Redis) {
            $ok = $this->redis->set($fenceKey, $token, ['PX' => 60_000]);
        } else {
            $ok = $this->redis->setex($fenceKey, 60, $token);
        }
        if ($ok === false || $ok === null) {
            throw new \KiwiCaptcha\Storage\ReplicaWaitException(sprintf('the replication fence write failed after %s', $what));
        }
        $this->waitAndVerify($what);
    }

    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        \KiwiCaptcha\VerifiedWaitGuard::refuseUnsupported($this->redis, $this->waitReplicas, 'RedisChainedChallengeStateStore');
    }

}
