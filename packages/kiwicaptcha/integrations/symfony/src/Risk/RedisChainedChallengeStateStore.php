<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

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
 * Deny/StepUp (or a cleared obligation) can never be reported as
 * persisted and then vanish on promotion. A lost terminal transition
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
     * Atomic create-or-get over the chain + obligation keys (same hash
     * tag). No obligation -> create the chain (v2 available) + the
     * obligation (same TTL). The obligation exists -> return the existing
     * chain id, raising the requiredRank/requiredAction when the new
     * reassessment is stronger, never lowering. The obligation points at
     * a missing/corrupt chain -> compare-delete the stale mapping and
     * create the chain fresh (a stale mapping can never block a
     * transaction). The pointed-at chain is a DECLARED key (KEYS[3]),
     * resolved by the caller from a plain read and re-verified inside
     * the script, so no key name is constructed from stored data; a
     * mapping that moved between the read and the script answers
     * 'moved' and the caller retries (bounded, fail-closed on
     * exhaustion). The reply is a three-element table {chainId, mutated,
     * verdict}: `mutated` is 1 exactly when the script performed a write
     * (the fresh creation, the stale-mapping repair or the rank raise).
     * It is 0 when the script only returned the existing chain. The
     * caller applies the verified WAIT durability barrier to the
     * mutating arms only.
     */
    private const CREATE_OR_GET_OBLIGATION_LUA = <<<'LUA'
-- Chain obligation create-or-get (chain + obligation, one hash tag).
-- EVERY key the script touches is a declared KEYS argument: KEYS[3] is the
-- chain the obligation mapping points at, resolved by the caller from a
-- plain read and RE-VERIFIED inside the script (a mapping that no longer
-- equals the caller's read answers 'moved' and the caller retries), so no
-- key name is ever constructed from stored data — the EVAL contract holds
-- on sharded/proxied/Redis Cloud topologies too.
local mapped = redis.call('GET', KEYS[2])
if mapped then
  if mapped ~= ARGV[11] then
    return {ARGV[11], 0, 'moved'}
  end
  local chained = redis.call('GET', KEYS[3])
  if chained then
    local ok, rec = pcall(cjson.decode, chained)
    if ok and type(rec) == 'table' and tonumber(rec['requiredRank']) then
      local newRank = tonumber(ARGV[6])
      if newRank > tonumber(rec['requiredRank']) then
        rec['requiredRank'] = newRank
        rec['requiredAction'] = ARGV[5]
        redis.call('SET', KEYS[3], cjson.encode(rec), 'KEEPTTL')
        return {ARGV[11], 1, ''}
      end
      return {ARGV[11], 0, ''}
    end
  end
  -- stale mapping: compare-delete + create fresh in the SAME script.
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
  expiresAt = tonumber(ARGV[9])
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
     * issue). A record without an expiry is corrupted state -> 'missing'
     * (never manufacture a lifetime).
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
     * Idempotent issuance: reserved(me) -> issued(stage2Nonce), KEEPTTL:
     * a state transition, never a delete, so the issued record lets a
     * retry recover the issued challenge instead of re-minting. Same
     * nonce again -> 'issued_same', verified with the same nonce ->
     * 'verified_same', any other nonce on an issued/completed chain, or
     * any nonce on a terminal step_up_required/denied chain -> 'conflict',
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
     * Terminal verification: issued(nonce) -> verified(nonce), KEEPTTL,
     * the terminal record kept until its TTL, atomically deleting the
     * obligation mapping (KEYS[2]) only if it still points at this
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
     * Terminal step-up: issued(nonce) -> step_up_required(nonce), KEEPTTL,
     * the terminal record kept until its TTL. The obligation mapping is
     * kept: the transaction stays bound to the step-up requirement, so a
     * later challenge request for the same transaction re-encounters the
     * terminal state (never a new stage-1). Same nonce again ->
     * 'step_up_required_same'; a different nonce or a non-issuable state
     * -> 'conflict'; absent -> 'missing'.
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
     * Terminal denial: issued(nonce) -> denied(nonce), KEEPTTL, the
     * terminal record kept until its TTL. The obligation mapping is
     * kept: the transaction stays bound to its final denial, so a later
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
    private const MARK_TRANSACTION_DENIED_LUA = <<<'LUA'
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
local rec = cjson.decode(existing)
if rec['obligationId'] ~= ARGV[2] then
  return 'obligation_moved'
end
local mapped = redis.call('GET', KEYS[2])
if mapped == false then
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
    private const MARK_TRANSACTION_STEP_UP_REQUIRED_LUA = <<<'LUA'
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
local rec = cjson.decode(existing)
if rec['obligationId'] ~= ARGV[2] then
  return 'obligation_moved'
end
local mapped = redis.call('GET', KEYS[2])
if mapped == false then
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
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'step_up_required_new'
LUA;

    /**
     * Atomic rearm: issued(expectedStage2Nonce) -> available, the
     * reservation fields + stage2Nonce cleared, KEEPTTL. A different
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
     * Owner-gated release: reserved(me) -> available, the reservation
     * holder's retry path: a refused or failed issuance must not burn
     * the ticket. A non-owner release is an atomic no-op: a failing
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
     * Deprecated legacy completion: reserved(owner) -> completed(
     * stage2Nonce), the historical name of the terminal-with-nonce
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
     * be unlinked by a stale delete). Returns 1 when the mapping was
     * deleted (a fresh mutation), 0 when it did not point at this chain —
     * the caller applies the verified WAIT durability barrier to the
     * deletion only.
     */
    private const DELETE_OBLIGATION_LUA = <<<'LUA'
-- Chain obligation compare-delete: only while it still points at this chain.
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
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
        private readonly string $namespace = 'kiwi',
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
    ) {
        $this->refuseVerifiedWaitOnUnsupportedPredisClients();
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
        // Durability barrier: the fresh chain + obligation write must
        // reach the configured replica count before the caller hands out
        // a ticket — a lost obligation would let the transaction restart
        // at stage 1 after a promotion.
        if ($this->waitReplicas > 0) {
            $this->waitAndVerify('the chain creation with its obligation');
        }
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $chainKey = $this->key($chainId);
        $obligationKey = $this->obligationKey($obligationId);

        // The pointed-at chain is resolved from a plain read and passed as
        // a declared key; a concurrent create-or-get that moved the
        // mapping between the read and the script answers 'moved' and the
        // loop re-reads and retries (bounded, then fail-closed — a
        // silently wrong chain must never be returned).
        for ($attempt = 0; $attempt < 3; ++$attempt) {
            $existing = $this->obligationChainId($obligationId);
            $reply = $this->evalScript(self::CREATE_OR_GET_OBLIGATION_LUA, [
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
        $status = \is_string($result) && \in_array($result, ['issued_new', 'issued_same', 'verified_same', 'conflict', 'not_owner', 'missing'], true)
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
        $result = $this->evalScript(self::MARK_VERIFIED_LUA, [
            $this->key($chainId),
            $this->obligationKey((string) $record['obligationId']),
        ], [$stage2Nonce, $chainId]);
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
        $result = $this->evalScript(self::MARK_STEP_UP_REQUIRED_LUA, [$this->key($chainId)], [$stage2Nonce]);
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
        $result = $this->evalScript(self::MARK_DENIED_LUA, [$this->key($chainId)], [$stage2Nonce]);
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
        $result = $this->evalScript(self::MARK_TRANSACTION_DENIED_LUA, [
            $this->key($chainId),
            $this->obligationKey($obligationId),
        ], [$chainId, $obligationId]);
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
        $result = $this->evalScript(self::MARK_TRANSACTION_STEP_UP_REQUIRED_LUA, [
            $this->key($chainId),
            $this->obligationKey($obligationId),
        ], [$chainId, $obligationId]);
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
        $rearmed = $this->evalScript(self::REARM_LUA, [$this->key($chainId)], [$expectedStage2Nonce]);
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
        $deleted = $this->evalScript(self::DELETE_OBLIGATION_LUA, [$this->obligationKey($obligationId)], [$chainId]);

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
        $raw = $this->evalScript(self::COMPLETE_LUA, [$this->key($chainId)], [$ownerToken, $stage2Nonce]);
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
        ];
    }

    /**
     * Fail-closed guard before every state transition: the record must
     * exist and strictly decode (a corrupt server record is a server
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
    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        if ($this->waitReplicas <= 0 || !($this->redis instanceof \Predis\Client)) {
            return;
        }
        $connection = $this->redis->getConnection();
        if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface) {
            throw new \InvalidArgumentException(
                'RedisChainedChallengeStateStore: verified-WAIT durability (waitReplicas > 0) is not supported on a Predis replication aggregate (Sentinel or master-slave) — WAIT is connection-affine, counting replicas of the connection it is sent on, and the aggregate\'s failure retry executes the WAIT on a replacement connection whose write offset is empty, so the acknowledgement proves nothing about the original write\'s replication. The verified barrier supports standalone Redis connections only; use a standalone connection with waitReplicas > 0, or keep waitReplicas = 0 on an aggregate.'
            );
        }
        if ($connection instanceof \Predis\Connection\Cluster\ClusterInterface) {
            throw new \InvalidArgumentException(
                'RedisChainedChallengeStateStore: verified-WAIT durability (waitReplicas > 0) is not supported on a Predis Redis Cluster client — WAIT is connection-relative and cannot be routed by slot. The verified barrier supports standalone Redis connections only; use a standalone connection with waitReplicas > 0, or keep waitReplicas = 0 on a cluster.'
            );
        }
        if ($connection === null) {
            // An in-memory stand-in with no real connection object (the
            // tests' fake clients skip the parent constructor): there is
            // no Parameters instance to carry a retry policy and the
            // stand-in overrides the command dispatch itself, so the
            // vendored retry wrapper never engages.
            return;
        }
        if ($connection instanceof \Predis\Connection\RelayConnection) {
            // A relay connection dispatches commands directly, bypassing
            // the vendored retry wrapper, so an explicit retry parameter
            // is inert there and cannot replay a mutation.
            return;
        }
        if (!$connection->getParameters()->isDisabledRetry()) {
            throw new \InvalidArgumentException(
                'RedisChainedChallengeStateStore: verified-WAIT durability (waitReplicas > 0) is not supported on a retry-enabled standalone Predis client — verified-WAIT durability requires that a durability-critical mutation is attempted exactly once on the connection whose subsequent WAIT establishes the replication offset, and a retry-enabled standalone Predis client can transparently re-execute the Lua mutation after a lost response. Retries must be disabled on the connection (remove the \'retry\' connection parameter), or keep waitReplicas = 0.'
            );
        }
    }
}
