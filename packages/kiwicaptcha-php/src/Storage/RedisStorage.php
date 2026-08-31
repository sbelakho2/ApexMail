<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\ChallengeRuntimeState;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\ChallengeRuntimeStateReadableInterface;
use KiwiCaptcha\ResumeDerivationClaimInterface;

/**
 * Redis-backed storage with atomic one-shot semantics.
 *
 * `consume()` is a transition, not a delete: an atomic Lua script marks
 * the record consumed and keeps it until its TTL. Replay protection is
 * the consumed marker, not absence, and the record can carry a
 * deterministic verification result (`consumed_result`) so a retry on an
 * already-consumed record returns the same outcome without re-deriving.
 * `commitResult()` stores that result atomically, only when the record
 * is consumed and has no result yet. Two concurrent consumers race inside
 * a single eval; Redis serializes the script, so exactly one caller wins
 * `consumedNow`, giving strict single-use under concurrency.
 *
 * Durability contract: the verified replication WAIT (fresh fence write
 * on the accepting connection, then WAIT) requires the configured
 * replica count to acknowledge each security-state mutation before the
 * caller learns success, and fails closed on a shortfall. It is
 * durability hardening rather than a consensus/linearizability guarantee:
 * Redis replication remains eventually consistent, and even
 * acknowledged writes can be lost under some failover and persistence
 * patterns. Redis itself states that WAIT does not make Redis a
 * strongly consistent (CP) store. Deployments that require
 * acknowledged-writes-can-never-vanish must back the one-shot security
 * state with a consensus-capable store instead.
 *
 * - phpredis (\Redis): evalSha() with the script's sha1 (`SCRIPT` `LOAD`
 *   once per script, sha cached per storage instance); a `NOSCRIPT`
 *   reply falls back to one plain eval() that ships the body.
 * - Predis: evalsha() the same way (the server must support Lua, i.e.
 *   any Redis >= 2.6); a `NOSCRIPT` ServerException re-runs `SCRIPT` `LOAD`
 *   once and retries evalsha().
 *
 * Records are stored as JSON in the canonical `ChallengeRecord` wire
 * keys schema, which is language-neutral: a Rust service using the same
 * Redis instance can read them and vice versa. The JSON is wrapped with
 * the three runtime fields `state` ("pending"|"consumed"|"cancelled"),
 * `consumed_result` (null | {valid, binding}) and `operation_identity`
 * (null | a bounded <= 128-byte logical-operation identity recorded
 * atomically with the pending→consumed transition via
 * {@see OperationIdentityAwareStorageInterface}). Two more optional
 * runtime fields exist only while a resume re-derivation claim is held:
 * `resume_owner` (hex owner token) and `resume_until` (epoch seconds);
 * they are absent otherwise and cleared atomically with the release and
 * the claim-bearing commit. The `cancelled` state
 * is the terminal marker of
 * {@see \KiwiCaptcha\CancellableStorageInterface::cancel()}. A pending
 * record flipped to cancelled is dead. The consume transition refuses
 * it, the consumed-state reads never surface it, and the
 * delete-if-pending cleanup never deletes it; the record is retained
 * until its TTL. The fresh flip carries the same verified replica wait
 * as the other durability-critical transitions. The runtime fields are
 * storage-layer additions after the canonical parse: `decode()` strips
 * them before {@see ChallengeRecord::fromArray()} so the strict
 * serde-mirror parser never sees them. That preserves deny_unknown_fields
 * parity with the Rust reader, which strips them the same way. The
 * record's TTL is the key expiration; every state transition preserves
 * it.
 *
 * Implements {@see \KiwiCaptcha\AtomicStorageInterface}: the fused
 * read-transition makes consume() strict single-use under concurrency.
 *
 * Implements {@see \KiwiCaptcha\ResumeDerivationClaimInterface}: the
 * resultless consumed-operation resume can claim the re-derivation
 * ownership with a random owner token and a bounded TTL embedded in the
 * record's runtime envelope. Exactly one concurrent same-operation
 * recovery derives and commits; the losers re-read the winner's
 * committed outcome. The claim, its compare-and-delete release and the
 * claim-clearing commit are all fused Lua scripts over the record key
 * only. The claim never lives in a second key, so every claim
 * transition is single-slot and safe on a Redis Cluster deployment,
 * where a second unhash-tagged key would raise `CROSSSLOT`. The
 * semantics mirror the Rust production verifier byte for byte.
 * Shared claim contract (both languages agree): a valid owner is
 * exactly 32 lowercase hex characters (rejected with
 * InvalidArgumentException at the storage boundary otherwise) and the
 * claim lease TTL is >= 1 second.
 *
 * The claim's runtime envelope fields: `resume_owner` (the hex owner
 * token) and `resume_until` (epoch seconds on the server clock) exist
 * only while a claim is held; they are absent otherwise and cleared
 * atomically by the release and by the claim-bearing commit. Every
 * envelope reader strips them with the other runtime fields before the
 * strict record parse.
 */
final class RedisStorage implements AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, \KiwiCaptcha\AtomicDeleteIfPendingInterface, \KiwiCaptcha\CancellableStorageInterface, \KiwiCaptcha\ChallengeRuntimeStateReadableInterface, \KiwiCaptcha\ReplicationBarrierInterface, ResumeDerivationClaimInterface
{
    /**
     * Atomic consume transition: GET the record; if present and not yet
     * consumed, flip `state` to "consumed" (preserving the key TTL). When
     * ARGV[1] is a non-empty JSON-escaped identity, the
     * `"operation_identity":null` marker is spliced to the identity in
     * the same script, so the identity lands atomically with the state
     * flip and the stored identity is provably the actual atomic consume
     * winner's. The identity has already passed
     * {@see OperationIdentity::validate()} before it reaches the script.
     * The 1..128-byte `[A-Za-z0-9_-]` alphabet excludes `%` and every
     * other Lua `string.gsub` replacement-template escape by
     * construction, so the raw replacement-string splice below can never
     * be interpreted as a template; a replacement function is
     * unnecessary. Returns nil for a missing record, else {json,
     * consumed_now, consumed_before, consumed_result_json}, where the
     * result is the committed JSON ("" when absent).
     */
    private const CONSUME_SCRIPT = <<<'LUA'
-- kiwicaptcha consume transition
--
-- CRITICAL: the record is NEVER re-encoded through cjson — re-encoding
-- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
-- and breaks both strict parsers. The state field is spliced into the
-- RAW stored JSON string (store() always writes the exact
-- `"state":"pending"` marker), and the logical-operation identity is
-- spliced into the `"operation_identity":null` marker in the SAME
-- script when a non-empty identity argument is given (an old record
-- without the marker — or a null identity — leaves it untouched). The
-- identity has passed the shared OperationIdentity::validate() gate
-- BEFORE the eval: 1..128 bytes of [A-Za-z0-9_-]. That alphabet is what
-- makes the gsub REPLACEMENT splice safe — `%` is the Lua replacement-
-- template escape and is excluded by construction, so ARGV[1] is never
-- interpreted as a template. The transition winner receives the UPDATED
-- bytes, so the recorded identity rides back on its own ConsumedRecord.
local v = redis.call("GET", KEYS[1])
if not v then
  return nil
end
local consumedNow = 0
local consumedBefore = 0
if string.find(v, '"state":"consumed"', 1, true) then
  consumedBefore = 1
else
  -- The pending-envelope guard: a genuinely issued pending record
  -- carries ONLY the null markers ("consumed_result":null and
  -- "operation_identity":null) and no claim lease fields. A pending
  -- envelope that ALSO carries a terminal or claim field (a non-null
  -- consumed_result, a non-null operation_identity, or any
  -- resume_owner / resume_until marker) is a corrupt or forged rewrite:
  -- the state marker was flipped without removing the carried fields.
  -- The transition REFUSES it with the missing/undecodable semantics
  -- (nil), so the verifier fails the token closed instead of
  -- re-deriving a fresh grant or installing the carried result. Only
  -- the consume transition itself may introduce these fields, and only
  -- into the envelope it just flipped.
  if (string.find(v, '"consumed_result":', 1, true) and not string.find(v, '"consumed_result":null', 1, true))
    or (string.find(v, '"operation_identity":', 1, true) and not string.find(v, '"operation_identity":null', 1, true))
    or string.find(v, '"resume_owner":"', 1, true)
    or string.find(v, '"resume_until":', 1, true) then
    return nil
  end
  local ttl = redis.call("TTL", KEYS[1])
  if ttl < 1 then ttl = 1 end
  local updated, n = string.gsub(v, '"state":"pending"', '"state":"consumed"', 1)
  if n ~= 1 then
    -- A cancelled record (or any other non-pending state) is never
    -- consumable: the gsub finds no pending marker, so the transition
    -- reports the record as missing (nil) and the verifier fails the
    -- token closed instead of ever redeeming it.
    return nil
  end
  if ARGV[1] ~= '' then
    local withIdentity, m = string.gsub(updated, '"operation_identity":null', '"operation_identity":' .. ARGV[1], 1)
    if m == 1 then
      updated = withIdentity
    end
  end
  redis.call("SET", KEYS[1], updated, "EX", ttl)
  consumedNow = 1
  v = updated
end
local s, e = string.find(v, '"consumed_result":%s*{', 1)
if s and e then
  local depth = 1
  local i = e + 1
  while depth > 0 and i <= #v do
    local c = string.sub(v, i, i)
    if c == '{' then depth = depth + 1
    elseif c == '}' then depth = depth - 1 end
    i = i + 1
  end
  return {v, consumedNow, consumedBefore, string.sub(v, e, i - 1)}
end
return {v, consumedNow, consumedBefore, 'null'}
LUA;

    /**
     * Atomic result commit: store {valid, binding} as `consumed_result`
     * only when the record exists, is consumed, and has no result yet.
     * Returns 1 on success, 0 otherwise. ARGV = {valid "1"|"0", binding,
     * has_binding "1"|"0"}.
     */
    /**
     * Atomic delete-if-pending cleanup: ONE script decides missing /
     * deleted-pending / consumed, closing the check-then-delete TOCTOU.
     * A record a concurrent redeemer consumes between the caller's
     * decision and this cleanup is observed in its consumed state here
     * and never deleted (the committed recovery evidence survives).
     * Returns {'missing'}, {'deleted-pending'}, or {'consumed', json}
     * with the retained envelope (the caller decodes the consumed state
     * from the same bytes; no second lookup).
     *
     * The deleted-pending transition is durability-critical: a burned
     * challenge that only vanished from the primary could reappear from
     * a stale replica after promotion and be redeemed. It therefore
     * carries the same verified WAIT contract as issuance, the
     * pending→consumed transition and the result commit (a violated
     * barrier raises {@see ReplicaWaitException}).
     */
    private const DELETE_IF_PENDING_SCRIPT = <<<'LUA'
-- kiwicaptcha delete-if-pending (atomic cleanup)
--
-- Same raw-splice rules as CONSUME_SCRIPT: the stored JSON is never
-- re-encoded through cjson (large integers would switch to scientific
-- notation). A consumed record is returned verbatim and kept. A
-- cancelled record is returned verbatim and kept too: the cancelled
-- challenge is dead but retained until its TTL, never eagerly deleted.
-- Only a pending record is deleted.
--
-- The DEL is a durability-critical write: the caller applies the same
-- verified WAIT barrier as the other transitions, so a burned challenge
-- that only vanished from the primary is substantially less likely to
-- be resurrected as pending by a promoted stale replica (WAIT is
-- durability hardening, not a consensus guarantee: Redis replication
-- remains eventually consistent across every failover pattern).
local v = redis.call("GET", KEYS[1])
if not v then
  return {'missing'}
end
if string.find(v, '"state":"consumed"', 1, true) then
  return {'consumed', v}
end
if string.find(v, '"state":"cancelled"', 1, true) then
  return {'cancelled', v}
end
redis.call("DEL", KEYS[1])
return {'deleted-pending'}
LUA;

    /**
     * Atomic cancellation transition: GET the record and decide. A
     * missing record returns nil. A consumed record is finalized and is
     * never cancelled ({'consumed'}). An already-cancelled record is
     * idempotent ({'cancelled'}). A pending record is flipped to
     * `"state":"cancelled"` in place, preserving the key TTL, and
     * returns {'cancelled-now'}. The same raw-splice rule as the consume
     * script applies: the stored JSON is never re-encoded through cjson.
     * The record is kept until its TTL. The cancelled marker is the
     * replay and redemption protection, not absence.
     */
    private const CANCEL_SCRIPT = <<<'LUA'
-- kiwicaptcha cancel transition
--
-- CRITICAL: the record is NEVER re-encoded through cjson — re-encoding
-- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
-- and breaks both strict parsers. The state field is spliced into the
-- RAW stored JSON string (store() always writes the exact
-- `"state":"pending"` marker), mirroring the consume transition. A
-- consumed record is terminal and never cancellable; a cancelled record
-- is idempotent. The flip preserves the key TTL.
local v = redis.call("GET", KEYS[1])
if not v then
  return nil
end
if string.find(v, '"state":"consumed"', 1, true) then
  return {'consumed'}
end
if string.find(v, '"state":"cancelled"', 1, true) then
  return {'cancelled'}
end
local ttl = redis.call("TTL", KEYS[1])
if ttl < 1 then ttl = 1 end
local updated, n = string.gsub(v, '"state":"pending"', '"state":"cancelled"', 1)
if n ~= 1 then
  return nil
end
redis.call("SET", KEYS[1], updated, "EX", ttl)
return {'cancelled-now'}
LUA;

    /**
     * The resume-claim TTL default: a crashed recovery leaves only this
     * short lease before a later retry may claim again (a poison marker
     * would block resultless recovery for its full TTL even when
     * nothing is running). Mirrors the Rust `CLAIM_TTL_SECS`. The
     * caller may pass a longer lease (the verifier passes a TTL that
     * covers the maximum supported derivation duration); the default
     * stays 60 seconds.
     */
    private const RESUME_CLAIM_TTL_SECS = 60;

    /**
     * Atomic resume-derivation claim, ONE key: the claim is embedded in
     * the record's runtime envelope (`resume_owner` / `resume_until`),
     * so the transition is a single-key splice that a Redis Cluster
     * deployment routes to one slot, never `CROSSSLOT`. ARGV[1] = the
     * random owner token, ARGV[2] = the claim TTL in seconds.
     */
    private const CLAIM_RESUME_SCRIPT = <<<'LUA'
-- kiwicaptcha resume-derivation claim
--
-- The re-derivation claim for a resultless consumed record (the resume
-- path): exactly one concurrent same-operation recovery may derive and
-- commit; the losers re-read and resolve the winner's committed outcome.
-- KEYS[1] = the record key only. ARGV[1] = the random owner token,
-- ARGV[2] = the claim TTL in seconds. The claim lives INSIDE the record
-- envelope: `"resume_owner":"<hex token>","resume_until":<epoch secs>`
-- is spliced before the envelope's closing brace (the record key TTL is
-- preserved), so this script touches exactly one key and is single-slot
-- on a Redis Cluster. A crash leaves only the short lease: once
-- resume_until passes, a later retry may claim again. The record checks
-- use the RAW markers (the same strategy as the rest of this storage
-- layer, which never re-encodes the record's JSON bytes): the envelope
-- stores `"consumed_result":null`, and a cjson decode would map a JSON
-- null to cjson.null, never Lua nil, refusing every resultless record.
local v = redis.call("GET", KEYS[1])
if not v then
  return nil
end
if not string.find(v, '"state":"consumed"', 1, true) then
  return nil
end
if not string.find(v, '"consumed_result":null', 1, true) then
  return nil
end
-- Live-claim check: refuse while a live claim is held. An owner marker
-- without a parseable expiry is treated as live (fail safe: never a
-- second unsynchronized derivation).
local untilStr = string.match(v, '"resume_until":(%d+)')
if string.find(v, '"resume_owner":"', 1, true) then
  local time = redis.call("TIME")
  local now = tonumber(time[1])
  if untilStr == nil or tonumber(untilStr) > now then
    return nil
  end
  -- Expired claim: strip the stale fields before appending the fresh
  -- ones. The fields always sit at the envelope's end (only this script
  -- family writes them); a shape that cannot be stripped is refused as
  -- still-claimed rather than duplicated.
  local stripped, n = string.gsub(v, ',"resume_owner":"[^"]*","resume_until":%d+}$', '}')
  if n ~= 1 then
    return nil
  end
  v = stripped
end
local time = redis.call("TIME")
local untilVal = tonumber(time[1]) + tonumber(ARGV[2])
local ttl = redis.call("TTL", KEYS[1])
if ttl < 1 then ttl = 1 end
local updated = string.sub(v, 1, -2) .. ',"resume_owner":"' .. ARGV[1] .. '","resume_until":' .. untilVal .. '}'
redis.call("SET", KEYS[1], updated, "EX", ttl)
return ARGV[1]
LUA;

    private const RELEASE_RESUME_SCRIPT = <<<'LUA'
-- kiwicaptcha resume-derivation claim release (compare-and-delete)
--
-- KEYS[1] = the record key only (the claim is embedded in the record
-- envelope; ONE key, single-slot on a Redis Cluster). ARGV[1] = the
-- owner token. The claim fields are cleared from the envelope only when
-- they still hold exactly this owner: a stale owner after a crash and
-- TTL expiry can never delete a newer recovery's claim. The record key
-- TTL is preserved.
local v = redis.call("GET", KEYS[1])
if not v then
  return 0
end
local updated, n = string.gsub(v, ',"resume_owner":"' .. ARGV[1] .. '","resume_until":%d+}$', '}')
if n ~= 1 then
  return 0
end
local ttl = redis.call("TTL", KEYS[1])
if ttl < 1 then ttl = 1 end
redis.call("SET", KEYS[1], updated, "EX", ttl)
return 1
LUA;

    private const COMMIT_SCRIPT = <<<'LUA'
-- kiwicaptcha commit result
--
-- Same raw-splice rule as CONSUME_SCRIPT: the stored JSON is never
-- re-encoded through cjson (large integers would switch to scientific
-- notation). The `"consumed_result":null` marker written by store() is
-- replaced in place. ONLY the small result object is encoded — valid
-- must be a REAL JSON boolean (matching the Rust commit Lua and the
-- strict ConsumedResult parser), binding a string or null.
--
-- The resume-path claim is an optional fencing precondition carried in
-- ARGV[4]: when non-empty, the envelope must hold a LIVE claim owned by
-- exactly this token before the protected mutation is written.
-- Ownership lost (missing, expired, or owned by a different token)
-- returns 2 with no write, so a stale owner whose claim expired
-- mid-derivation can never commit, and the successful write clears the
-- claim fields in the same atomic transition. The claim is embedded in
-- the record envelope, so this script touches exactly one key
-- (single-slot on a Redis Cluster, never CROSSSLOT). Callers without a
-- claim pass ARGV[4] = '': byte-identical legacy behavior.
local v = redis.call("GET", KEYS[1])
if not v then
  return 0
end
if not string.find(v, '"state":"consumed"', 1, true) then
  return 0
end
if not string.find(v, '"consumed_result":null', 1, true) then
  return 0
end
local claim = (ARGV[4] ~= nil) and (ARGV[4] ~= '')
if claim then
  -- Fencing: a live claim owned by this exact token. The owner token is
  -- hex ([0-9a-f]), so it is safe inside the Lua pattern. The claim
  -- must be LIVE: an expired claim no longer fences (the stale owner
  -- may not commit, exactly the Rust GET-on-an-expired-key behavior).
  local untilStr = string.match(v, '"resume_owner":"' .. ARGV[4] .. '","resume_until":(%d+)')
  local time = redis.call("TIME")
  local now = tonumber(time[1])
  if untilStr == nil or tonumber(untilStr) <= now then
    return 2
  end
end
local encoded = cjson.encode({
  valid = (ARGV[1] == '1'),
  binding = (ARGV[3] == "0") and cjson.null or ARGV[2]
})
local updated, n = string.gsub(v, '"consumed_result":null', '"consumed_result":' .. encoded, 1)
if n ~= 1 then
  return 0
end
if claim then
  local cleared, m = string.gsub(updated, ',"resume_owner":"' .. ARGV[4] .. '","resume_until":%d+}$', '}')
  if m ~= 1 then
    return 0
  end
  updated = cleared
end
local ttl = redis.call("TTL", KEYS[1])
if ttl < 1 then ttl = 1 end
redis.call("SET", KEYS[1], updated, "EX", ttl)
return 1
LUA;

    /**
     * The verified-WAIT durability barrier (waitReplicas > 0) is
     * supported on standalone Redis connections only. A Predis client on
     * a replication aggregate (Sentinel or master-slave) or on a Redis
     * cluster aggregate is refused at construction with waitReplicas > 0,
     * and so is a standalone Predis client with command retries enabled.
     * WAIT is connection-affine: it counts replicas of the connection it
     * is sent on. A replication aggregate's failure retry executes the
     * WAIT on a replacement connection whose write offset is empty, so
     * the acknowledgement would prove nothing about the original
     * write's replication. A cluster aggregate cannot route a keyless
     * WAIT at all. A future pinned-master implementation may restore
     * Sentinel support; keep waitReplicas = 0 on an aggregate today.
     *
     * @param int $waitReplicas   when > 0, every durability-critical write
     *                            (issuance, the pending→consumed
     *                            transition, the deterministic-result
     *                            commit, and the terminal delete-if-pending
     *                            deletion) is followed by a Redis WAIT
     *                            whose acknowledgement count is verified.
     *                            Fewer than waitReplicas acked replicas
     *                            raises {@see ReplicaWaitException}
     *                            (fail closed: the guarantee is
     *                            unconditional, never silently downgraded).
     *                            Async-replication failover can otherwise
     *                            lose a write or resurrect a consumed
     *                            record from a stale replica. Supported
     *                            PHP client + topology + retry matrix:
     *                            phpredis direct connection -> supported
     *                            (not subject to the Predis topology and
     *                            retry checks). Predis standalone with
     *                            retries disabled (the default) ->
     *                            supported: each durability-critical
     *                            mutation is attempted exactly once on the
     *                            connection whose WAIT establishes the
     *                            replication offset. Predis standalone
     *                            with retries enabled -> refused at
     *                            construction: the vendored command-retry
     *                            wrapper can transparently re-execute the
     *                            Lua mutation after a lost response, so
     *                            the returned result may describe the
     *                            second invocation rather than the one
     *                            that mutated. Predis Sentinel or
     *                            master-slave replication aggregate with
     *                            any retry setting -> refused: WAIT is
     *                            connection-relative. A replication
     *                            aggregate's failure retry executes the
     *                            WAIT on a replacement connection whose
     *                            write offset is empty, and a cluster
     *                            aggregate cannot route a keyless WAIT by
     *                            slot. Predis cluster aggregate with any
     *                            retry setting -> refused. Keep
     *                            waitReplicas = 0 on an aggregate or a
     *                            retry-enabled standalone client.
     * @param int $waitTimeoutMs  wait timeout in milliseconds (default 100).
     * @param int $ttlMarginSecs  extra retention on the record beyond token
     *                            validity: TTL = expires_at - now + margin.
     *                            Must exceed max clock skew + failover
     *                            margin so a replayed token can never land
     *                            on an already-expired state.
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly string $prefix = 'kiwicaptcha:',
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
        private readonly int $ttlMarginSecs = 0,
    ) {
        $this->refuseVerifiedWaitOnUnsupportedPredisClients();
    }

    /**
     * Refuse the verified-WAIT hardening on Predis clients whose command
     * dispatch can hide or re-execute the durability-critical write:
     * replication aggregates, cluster aggregates, and retry-enabled
     * standalone connections.
     *
     * WAIT is connection-relative: it counts replicas of the connection
     * it is sent on and carries no key. A Predis replication aggregate
     * (Sentinel or master-slave) wraps every command in failure-retry
     * logic: on a communication failure it wipes its server list,
     * rediscovers the topology, and retries the command on a NEW
     * connection to the promoted node. The verified WAIT goes through
     * the same aggregate. A primary failure between the write and the
     * WAIT retries the WAIT on a replacement connection whose write
     * offset is zero, so the acknowledgement would prove nothing about
     * the original write's replication, yet the barrier would treat it
     * as proof. The check therefore refuses the whole replication
     * aggregate family with waitReplicas > 0, fail closed before any
     * write can run. A Redis cluster aggregate is refused as well, since Predis
     * dispatches every command to a node by key slot and a keyless raw
     * WAIT has no slot; the dispatch throws instead of reaching any
     * node. A fake-slot workaround would be unsafe (the aggregate would
     * send WAIT on a node other than the one that carried the write).
     *
     * A standalone Predis client is refused when its connection
     * parameters report command retries enabled. Predis 3.5.1 disables
     * retries by default, but an explicit `retry` connection parameter
     * arms the vendored retry machinery.
     * {@see \Predis\Client::executeCommand()} then wraps every command
     * on a standalone (non-aggregate, non-relay) connection in the
     * configured policy, with `callWithRetry(...)` and a disconnect
     * callback. A lost response makes the client disconnect, reconnect,
     * and transparently re-execute the command, including the Lua eval
     * that carries the durability-critical mutation. The first
     * invocation may have performed the mutation while the returned
     * result describes the second invocation. A delete-if-pending eval
     * whose first execution performed the terminal DEL is retried into
     * a 'missing' reply, and the verified WAIT that must follow the
     * mutation is skipped although the deletion happened. The refusal
     * applies exactly where the vendored retry wrapper engages, which
     * {@see \Predis\Connection\Parameters::isDisabledRetry()} reports.
     * A relay connection dispatches commands directly without the
     * retry wrapper, and an in-memory stand-in without a real
     * connection object has no retry configuration to inspect.
     *
     * Supported topology is standalone Redis only. The checks target
     * {@see \Predis\Connection\Replication\ReplicationInterface}
     * (implemented by SentinelReplication and MasterSlaveReplication),
     * {@see \Predis\Connection\Cluster\ClusterInterface}
     * (implemented by the cluster aggregates), covering every Predis
     * aggregate family, and the retry state of a standalone node
     * connection. A future pinned-master implementation may
     * restore Sentinel support.
     */
    /**
     * The public failed-barrier replay guard entry
     * ({@see \KiwiCaptcha\ReplicationBarrierInterface}, the verifier's
     * stored-success acceptance fence): the same causal fence + verified
     * WAIT as every durability-critical transition, through the same
     * {@see self::waitAndVerify()} path. A wait-free storage
     * (waitReplicas = 0) has no barrier to re-establish and returns
     * immediately.
     */
    public function establishReplicationFence(string $what): void
    {
        if ($this->waitReplicas <= 0) {
            return;
        }
        $this->waitAndVerify($what);
    }

    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        \KiwiCaptcha\VerifiedWaitGuard::refuseUnsupported($this->client, $this->waitReplicas, 'RedisStorage');
    }


    public function store(ChallengeRecord $record): void
    {
        $key = $this->prefix.$record->nonce;
        $value = json_encode(
            $record->toArray() + ['state' => 'pending', 'consumed_result' => null, 'operation_identity' => null],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
        $ttl = max(1, $record->expiresAt - time() + $this->ttlMarginSecs);

        if ($this->client instanceof \Redis) {
            $this->client->set($key, $value, ['EX' => $ttl]);
        } else {
            $this->client->set($key, $value, 'EX', $ttl);
        }

        if ($this->waitReplicas > 0) {
            $this->waitAndVerify('challenge issuance');
        }
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if ($raw === false || $raw === null) {
            return null;
        }

        return $this->decode((string) $raw);
    }

    /**
     * Atomic consume transition. The verified WAIT durability barrier
     * applies to the fresh pending-to-consumed transition only, the
     * write that actually happened. A replay of an already-consumed
     * record or a missing record performs no write, so no WAIT is
     * issued and an idempotent retry can never turn a replica outage into a storage
     * failure.
     */
    public function consume(string $nonce): ?ConsumedRecord
    {
        return $this->doConsume($nonce, '');
    }

    /**
     * Atomic consume transition recording the logical-operation identity
     * with the state flip. The verified WAIT durability barrier applies
     * to the fresh pending-to-consumed transition only, the write that
     * actually happened. A replay of an already-consumed record or a
     * missing record performs no write, so no WAIT is issued and an
     * idempotent retry can never turn a replica outage into a storage
     * failure.
     */
    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        // The identity is validated against the narrow shared alphabet,
        // see {@see OperationIdentity::validate()} (1..128 bytes of
        // [A-Za-z0-9_-]), before it can reach the Lua splice. A malformed
        // identity is rejected, never silently dropped, and the record is
        // left untouched. The alphabet also makes the raw string.gsub
        // replacement splice safe: `%` is a replacement-template escape
        // in Lua and is excluded by construction.
        $identityArg = '';
        $validated = OperationIdentity::validate($operationIdentity);
        if ($validated !== null) {
            $identityArg = json_encode($validated, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        }

        return $this->doConsume($nonce, $identityArg);
    }

    /**
     * The shared consume implementation of both public entry points
     * (the plain consume passes '' as the identity argument, which the
     * Lua leaves untouched). The returned envelope is parsed once by
     * {@see self::decodeEnvelope()}: the ChallengeRecord, the committed
     * result and the recorded operation identity are all derived from
     * a single json_decode of the same bytes.
     */
    private function doConsume(string $nonce, string $identityArg): ?ConsumedRecord
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::CONSUME_SCRIPT, [$key, $identityArg], 1);
        if ($raw === false || $raw === null || !\is_array($raw)) {
            return null;
        }

        // Lua tables are 1-indexed; normalize before destructuring.
        $parts = array_values($raw);
        if (\count($parts) < 4) {
            return null;
        }
        [$json, $consumedNow, $consumedBefore, $resultBinding] = $parts;

        // Durability barrier: the verified WAIT runs only when the
        // pending→consumed transition actually happened (consumedNow) —
        // the write the barrier exists to replicate. An already-consumed
        // replay or a missing record performed no write, so no WAIT is
        // issued: an idempotent retry must not turn a replica outage
        // into a storage failure. The WAIT acknowledgement count proves
        // that at least the configured number of replicas received the
        // write; it does not constrain which replicas a future failover
        // manager promotes. Replay-safe promotion additionally requires
        // the threshold to cover every eligible failover target or
        // promotion gating.
        if ($this->waitReplicas > 0 && (bool) $consumedNow) {
            $this->waitAndVerify('the pending→consumed transition');
        }

        $envelope = $this->decodeEnvelope((string) $json);
        if ($envelope === null) {
            return null;
        }
        $result = null;
        if ((string) $resultBinding !== 'null' && (string) $resultBinding !== '') {
            $obj = json_decode((string) $resultBinding, true);
            if (\is_array($obj)) {
                $result = new ConsumedResult(
                    (int) ($obj['valid'] ?? 0) === 1,
                    \is_string($obj['binding'] ?? null) ? $obj['binding'] : null,
                );
            }
        }

        return new ConsumedRecord($envelope['record'], (bool) $consumedNow, (bool) $consumedBefore, $result, $envelope['identity']);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || $raw === '' || !str_contains($raw, '"state":"consumed"')) {
            return null;
        }

        return $this->decodeConsumedEnvelope($raw);
    }

    /**
     * Decode a ConsumedRecord entirely from the stored envelope bytes —
     * the record, the committed result and the operation identity are all
     * parsed from the same $raw, with NO Redis operation. This is the
     * single-snapshot guarantee of {@see ChallengeRuntimeStateReadableInterface}:
     * the consumed state is never reconstructed from two separately timed
     * reads (a retained record can expire between them, or a takeover can
     * move it). The caller always sees exactly the bytes one GET
     * observed.
     */
    private function decodeConsumedEnvelope(string $raw): ?ConsumedRecord
    {
        $envelope = $this->decodeEnvelope($raw);
        if ($envelope === null) {
            return null;
        }
        $result = null;
        $resultJson = self::extractConsumedResultJson($raw);
        if ($resultJson !== null) {
            $result = $this->decodeResult($resultJson);
        }

        return new ConsumedRecord($envelope['record'], false, true, $result, $envelope['identity']);
    }

    /**
     * Extract the `"consumed_result": {...}` JSON object from a stored
     * envelope with a brace-depth scanner, the same matching the consume
     * Lua performs (CONSUME_SCRIPT). From the object's opening brace,
     * nesting counts up on '{' and down on '}', and the object ends only
     * at the balancing '}'. A non-greedy regex would truncate at the
     * first '}' — e.g. a binding string containing braces (a foreign
     * writer; the PHP issuer's identifier alphabet excludes them today,
     * but the parser must not silently degrade a committed result to
     * resultless on one).
     *
     * Returns the matched object text (starting at '{'), or null when no
     * consumed_result marker is present.
     */
    private static function extractConsumedResultJson(string $raw): ?string
    {
        $marker = '"consumed_result":';
        $pos = strpos($raw, $marker);
        if ($pos === false) {
            return null;
        }
        $start = strpos($raw, '{', $pos + \strlen($marker));
        if ($start === false) {
            return null;
        }
        $depth = 0;
        $len = \strlen($raw);
        for ($i = $start; $i < $len; $i++) {
            $c = $raw[$i];
            if ($c === '{') {
                $depth++;
            } elseif ($c === '}') {
                $depth--;
                if ($depth === 0) {
                    return substr($raw, $start, $i - $start + 1);
                }
            }
        }

        return null;
    }

    /**
     * The atomic cleanup transition: ONE script decides missing /
     * deleted-pending / consumed / cancelled (the same contract as
     * {@see \KiwiCaptcha\AtomicDeleteIfPendingInterface}, plus the
     * cancelled state: a cancelled record is dead but retained until its
     * TTL, exactly like a consumed one).
     *
     * The deleted-pending transition is durability-critical and carries
     * the same verified WAIT contract as issuance, the pending-to-consumed
     * transition and the result commit. The delete must reach the
     * configured replica count before the caller may treat the challenge
     * as burned, or a promoted stale replica could resurrect it as
     * pending and let it be redeemed. A violated barrier surfaces the
     * same fail-closed {@see ReplicaWaitException} as the other
     * transitions. No WAIT is issued for missing, consumed or cancelled,
     * since no mutation occurred.
     */
    public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::DELETE_IF_PENDING_SCRIPT, [$key], 1);
        if (!\is_array($raw)) {
            throw new \RuntimeException('delete-if-pending: unexpected storage reply');
        }
        $parts = array_values($raw);
        $state = (string) ($parts[0] ?? '');
        if ($state === 'missing') {
            // No mutation occurred; the WAIT barrier only guards writes.
            return new \KiwiCaptcha\DeleteIfPendingResult($state);
        }
        if ($state === 'deleted-pending') {
            // Durability barrier: the delete must reach the configured
            // replica count before the caller may treat the challenge as
            // burned. The WAIT acknowledgement count proves that at least
            // the configured number of replicas received the write; it
            // does not constrain which replicas a future failover manager
            // promotes. Replay-safe promotion additionally requires the
            // threshold to cover every eligible failover target or
            // promotion gating.
            if ($this->waitReplicas > 0) {
                $this->waitAndVerify('the delete-if-pending transition');
            }

            return new \KiwiCaptcha\DeleteIfPendingResult($state);
        }
        if ($state === 'cancelled') {
            // A cancelled record is dead but retained until its TTL — the
            // cleanup never deletes it, so a cancellation is
            // substantially less likely to be resurrected as pending by
            // a promoted stale replica (WAIT is durability hardening,
            // not a consensus guarantee). No
            // ConsumedRecord rides along: the cancelled state is not
            // consumed evidence. No WAIT: no mutation occurred.
            return new \KiwiCaptcha\DeleteIfPendingResult('cancelled');
        }
        // consumed: decode the retained envelope from the returned bytes
        // (the committed result and the recorded operation identity ride
        // along — no second lookup). No WAIT: no mutation occurred, the
        // record was already durably consumed.
        $json = (string) ($parts[1] ?? '');
        $envelope = $this->decodeEnvelope($json);
        if ($envelope === null) {
            throw new \RuntimeException('delete-if-pending: undecodable consumed envelope');
        }
        $result = null;
        $resultJson = self::extractConsumedResultJson($json);
        if ($resultJson !== null) {
            $result = $this->decodeResult($resultJson);
        }

        return new \KiwiCaptcha\DeleteIfPendingResult('consumed', new ConsumedRecord($envelope['record'], false, true, $result, $envelope['identity']));
    }

    /**
     * The atomic cancellation transition: pending -> cancelled in ONE
     * script, closing the check-then-flip TOCTOU. A record a concurrent
     * redeemer consumes between the caller's decision and the flip is
     * observed in its consumed state here and never cancelled. A missing
     * record returns null (a cancellation of a never-issued or expired
     * nonce is idempotent success upstream); a consumed record returns
     * {'consumed'} (finalized — never cancellable); an already-cancelled
     * record returns {'cancelled'} (idempotent); the pending->cancelled
     * flip returns {'cancelled-now'}.
     *
     * The pending->cancelled transition is durability-critical and
     * carries the same verified WAIT contract as the other transitions:
     * a cancelled challenge that only vanished from the primary could
     * resurrect as pending on a promoted stale replica and be redeemed.
     * The flip must reach the configured replica count before the caller
     * may report the cancellation. No WAIT is issued for missing,
     * consumed or already-cancelled, since no mutation occurred.
     */
    public function runtimeState(string $nonce): ChallengeRuntimeState
    {
        // ONE GET: the state is decoded from the same bytes the
        // pending->consumed/cancelled transitions wrote, never from two
        // separate reads that could race.
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || $raw === '') {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
        }
        if (str_contains($raw, '"state":"cancelled"')) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Cancelled, $this->decode($raw));
        }
        if (str_contains($raw, '"state":"consumed"')) {
            // Decoded entirely from the same $raw this method already
            // holds — never a second GET.
            $consumed = $this->decodeConsumedEnvelope($raw);

            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Consumed, $consumed?->record, $consumed);
        }

        return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Pending, $this->decode($raw));
    }

    public function cancel(string $nonce): ?\KiwiCaptcha\CancellationResult
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::CANCEL_SCRIPT, [$key], 1);
        if ($raw === false || $raw === null || !\is_array($raw)) {
            return null;
        }
        $parts = array_values($raw);
        $state = (string) ($parts[0] ?? '');
        if ($state === 'cancelled-now') {
            // Durability barrier: the flip must reach the configured
            // replica count before the caller may treat the challenge as
            // cancelled (see the method docblock).
            if ($this->waitReplicas > 0) {
                $this->waitAndVerify('the pending→cancelled transition');
            }
        }

        return new \KiwiCaptcha\CancellationResult($state);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::COMMIT_SCRIPT, [$key, $valid ? '1' : '0', $binding ?? '', $binding === null ? '0' : '1'], 1);
        $committed = $raw === 1 || $raw === '1' || $raw === true;

        // Durability barrier: a committed deterministic result that only
        // lives on the primary would be lost on promotion, degrading a
        // retry to ConsumeIndeterminate. Callers treat commit as
        // best-effort, so a barrier failure cannot change the outcome; it
        // only surfaces the safe degraded state on the next retry.
        if ($committed && $this->waitReplicas > 0) {
            $this->waitAndVerify('the result commit');
        }

        return $committed;
    }

    /**
     * Atomically claim the re-derivation ownership of a consumed,
     * resultless record (the resume path): exactly one concurrent
     * same-operation recovery may derive and commit; the losers re-read
     * and resolve the winner's committed outcome. ONE Lua script over
     * the record key fuses the claimability check with the envelope
     * splice of the fresh random owner token and its expiry
     * (`resume_owner` / `resume_until`, epoch seconds on the server
     * clock). The claim lives in the record envelope, never in a second
     * key: every claim transition is single-slot and safe on a Redis
     * Cluster deployment, where a second unhash-tagged key would raise
     * `CROSSSLOT`. The claimability check requires the record to exist,
     * be consumed and carry no committed result yet; pending,
     * committed, missing and cancelled records are refused, and so is a
     * record with a live claim (an expired claim is re-claimable). A
     * crash leaves only the short lease, exactly what the TTL covers.
     *
     * Returns the owner token when this caller won the claim, or null
     * when the claim was refused (not claimable, or another recovery
     * currently holds a live claim). Fail closed: owner-generation
     * failure (the secure RNG) or a storage failure throws, so a
     * distributed mutex owner never falls back to a repeatable process
     * identifier and the caller never falls back to an unsynchronized
     * derive storm.
     *
     * @param int $ttlSecs the claim lease length in seconds (>= 1). The
     *                     verifier passes a TTL that covers the maximum
     *                     supported derivation duration so a legitimate
     *                     derivation never outlives its own claim; the
     *                     default 60 mirrors the Rust `CLAIM_TTL_SECS`.
     *                     Shared claim contract: a TTL below 1 second is
     *                     rejected at the storage boundary with an
     *                     InvalidArgumentException.
     *
     * @throws \InvalidArgumentException when $ttlSecs is below 1
     */
    public function claimResumeDerivation(string $nonce, int $ttlSecs = self::RESUME_CLAIM_TTL_SECS): ?string
    {
        if ($ttlSecs < 1) {
            throw new \InvalidArgumentException('the resume claim TTL must be at least 1 second');
        }
        $recordKey = $this->prefix.$nonce;
        // Secure RNG fail closed: a repeatable owner token could let two
        // recoveries in one process observe the same apparent owner
        // across a lease expiry. Generation failure propagates as a
        // storage failure and the recovery answers StorageUnavailable.
        $owner = bin2hex(random_bytes(16));
        $raw = $this->evalScript(self::CLAIM_RESUME_SCRIPT, [$recordKey, $owner, (string) $ttlSecs], 1);
        if ($raw === false || $raw === null) {
            return null;
        }

        return (string) $raw;
    }

    /**
     * Compare-and-delete the resume claim: only the claim's owner may
     * release it (a stale owner after a crash and TTL expiry can never
     * delete a newer recovery's claim). ONE Lua script over the record
     * key compares and clears the embedded claim fields. Returns true
     * when the release cleared the claim, false when the claim is
     * missing or owned by another token. No replica wait: the release
     * is a lease cleanup, not durability-critical state (the same as
     * the Rust side).
     *
     * Shared claim contract (mirrors the Rust verifier): a valid owner
     * is exactly 32 lowercase hex characters, and any other shape is
     * rejected at the storage boundary with an InvalidArgumentException.
     * The validation runs before any interpolation into the Lua pattern,
     * where non-hex characters would be pattern syntax.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function releaseResumeDerivation(string $nonce, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $recordKey = $this->prefix.$nonce;
        $raw = $this->evalScript(self::RELEASE_RESUME_SCRIPT, [$recordKey, $owner], 1);

        return $raw === 1 || $raw === '1' || $raw === true;
    }

    /**
     * The resume-path commit clears the re-derivation claim atomically
     * with the result write. The same `COMMIT_SCRIPT` takes the owner
     * token as a fencing precondition: ownership lost, whether missing,
     * expired, or owned by a different token, is refused before any
     * write. The script clears the embedded claim fields in the same
     * run as the result splice, over the record key only. The verified
     * replica wait applies to the fresh mutation exactly as on the
     * plain commit. Returns true only when the result was stored and
     * the claim cleared; false when the record is not a resultless
     * consumed record, or this caller no longer holds a live claim. The
     * caller then re-reads the retained state and resolves the winner's
     * committed outcome, mirroring the Rust
     * `commit_result_clearing_claim`.
     *
     * Shared claim contract (mirrors the Rust verifier): a valid owner
     * is exactly 32 lowercase hex characters, and any other shape is
     * rejected at the storage boundary with an InvalidArgumentException.
     * The validation runs before any interpolation into the Lua pattern,
     * where non-hex characters would be pattern syntax.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $recordKey = $this->prefix.$nonce;
        $raw = $this->evalScript(self::COMMIT_SCRIPT, [$recordKey, $valid ? '1' : '0', $binding ?? '', $binding === null ? '0' : '1', $owner], 1);
        $committed = $raw === 1 || $raw === '1' || $raw === true;

        if ($committed && $this->waitReplicas > 0) {
            $this->waitAndVerify('the result commit');
        }

        return $committed;
    }

    /**
     * The shared resume-claim owner contract: exactly 32 lowercase hex
     * characters (the bin2hex of 16 random bytes the claim API mints).
     * A valid owner is safe inside the Lua patterns of the release and
     * commit scripts, where characters like '-' and '%' are pattern
     * syntax; any other shape is rejected here, at the storage boundary.
     *
     * @throws \InvalidArgumentException
     */
    private function assertValidResumeOwner(string $owner): void
    {
        if (preg_match('/^[0-9a-f]{32}$/D', $owner) !== 1) {
            throw new \InvalidArgumentException('the resume claim owner must be exactly 32 lowercase hex characters');
        }
    }

    public function delete(string $nonce): void
    {
        $this->client->del($this->prefix.$nonce);
    }

    /**
     * Cached sha1 of every static Lua script (`SCRIPT` `LOAD` once per
     * script, cached for the storage instance's lifetime — the mirror
     * of RedisRiskStateStore's sha cache). The scripts are immutable
     * class constants, so a cached sha can never go stale within a
     * process; a server-side `SCRIPT` `FLUSH` or restart is absorbed by
     * the `NOSCRIPT` fallback below, which reloads and retries.
     *
     * @var array<string, string>
     */
    private array $scriptShas = [];

    /**
     * Diagnostic counter of stored-envelope json_decode calls — the
     * single-parse contract of {@see self::decodeEnvelope()}. Internal
     * test seam; never read by production code paths.
     */
    private int $envelopeDecodes = 0;

    /**
     * Run one of the class's Lua scripts through `EVALSHA` with the
     * cached sha instead of shipping the ~2KB source on every call
     * (the mirror of RedisRiskStateStore::runScript). The sha is
     * established once per script per process with `SCRIPT` `LOAD`. A
     * `NOSCRIPT` reply (the script cache was flushed or the server
     * restarted) falls back to reloading and, on phpredis, to one
     * plain `EVAL`, so the observable transition semantics and the
     * error propagation of the previous EVAL-only path are unchanged.
     *
     * @param list<mixed> $args    key(s) then script arguments
     * @param int         $numKeys number of leading keys in $args
     */
    private function evalScript(string $script, array $args, int $numKeys): mixed
    {
        if ($this->client instanceof \Redis) {
            $sha = $this->shaOf($script);
            try {
                $result = $this->client->evalSha($sha, $args, $numKeys);
                if ($result !== false) {
                    return $result;
                }
                // phpredis builds exist that report a missing script as
                // a plain false instead of raising the server's
                // `NOSCRIPT` error, and false is also phpredis's mapping
                // of a Lua nil reply. Every script of this class
                // replies nil only on a no-mutation path (a missing,
                // refused or terminal record), so treating false as a
                // suspected `NOSCRIPT` and re-running through plain EVAL
                // is safe: the re-run is idempotent and returns the
                // same answer, while a genuine `NOSCRIPT` is repaired.
            } catch (\RedisException $e) {
                if (!self::isNoScriptError($e)) {
                    throw $e;
                }
            }

            return $this->client->eval($script, $args, $numKeys);
        }

        $sha = $this->shaOf($script);
        try {
            return $this->client->evalsha($sha, $numKeys, ...$args);
        } catch (\Predis\Response\ServerException $e) {
            if (!str_contains($e->getMessage(), 'NOSCRIPT')) {
                throw $e;
            }
            // The server lost its script cache (`SCRIPT` `FLUSH` or a
            // restart): load the body again, refresh the cache, and
            // retry `EVALSHA` once. A failure of the retry propagates
            // raw, exactly like a failed EVAL did.
            $sha = $this->scriptShas[$script] = $this->loadScript($script);

            return $this->client->evalsha($sha, $numKeys, ...$args);
        }
    }

    /**
     * Whether a phpredis exception carries the server's `NOSCRIPT` error
     * (the missing-script reply that triggers the reload fallback).
     */
    private static function isNoScriptError(\RedisException $e): bool
    {
        return stripos($e->getMessage(), 'NOSCRIPT') !== false;
    }

    /** Cached sha of a script, `SCRIPT` LOADing it exactly once. */
    private function shaOf(string $script): string
    {
        return $this->scriptShas[$script] ??= $this->loadScript($script);
    }

    /**
     * `SCRIPT` `LOAD` the body and return the server's sha. Any client
     * failure propagates raw, like every other command of this class.
     */
    private function loadScript(string $script): string
    {
        $sha = $this->client instanceof \Redis
            ? $this->client->script('load', $script)
            : $this->client->script('LOAD', $script);
        if (!\is_string($sha) || $sha === '') {
            throw new \RuntimeException('SCRIPT LOAD returned no sha for the storage script');
        }

        return $sha;
    }

    /**
     * The durability barrier: the causal replication fence write
     * followed by the verified WAIT, executed under the durability
     * session when the client exposes one.
     *
     * The fence write happens under the same authority epoch as the
     * security-final mutation that preceded the barrier. When the
     * client is the bundle's {@see AuthorityGuardedPredisClient}
     * wrapper (ha_authority "pinned_primary"), the whole
     * [fence write, WAIT] pair runs inside `withDurabilitySession()`.
     * The session forces the zero-stale authority verification AND the
     * connection-generation equality (the guard's cached entry must
     * match the connection about to execute) before every barrier
     * command. A reconnect to a changed authority between the
     * mutation and the WAIT is therefore observed by the barrier's own
     * verification and refuses before the fence write or the WAIT
     * executes. The WAIT runs only on the still-pinned authority
     * connection. The structural `method_exists` seam keeps the core
     * package free of a bundle dependency: without the wrapper (the
     * plain client path) the barrier is the same fence + WAIT without
     * the authority checks, exactly the pre-pinned_primary behavior.
     *
     * The causal fence: a fresh write on the accepting connection
     * immediately before the WAIT. Replication is ordered, so a
     * replica that acknowledges the fence has advanced through the
     * preceding primary stream (the originally unproven mutation
     * included). A bare WAIT on a connection that wrote nothing cannot
     * prove another connection's write.
     */
    private function waitAndVerify(string $what): void
    {
        $barrier = function () use ($what): void {
            $this->writeReplicationFence($what);
            $this->wait($what);
        };
        if (\is_object($this->client) && method_exists($this->client, 'withDurabilitySession')) {
            // The pinned-primary guarded wrapper: the fence write and
            // the WAIT execute under the same authority epoch as the
            // mutation, with the zero-stale verification and the
            // connection-generation equality before every command.
            $this->client->withDurabilitySession($barrier);

            return;
        }
        $barrier();
    }

    /**
     * The causal replication fence write: a fresh random-token write on
     * the accepting connection, immediately before the WAIT. The key
     * TTL bounds the fence's lifetime (60 s), so a stale fence can
     * never grow unbounded. A failed write fails the barrier closed
     * with the typed {@see ReplicaWaitException}.
     */
    private function writeReplicationFence(string $what): void
    {
        $fenceKey = $this->prefix.'replication-fence';
        $token = bin2hex(random_bytes(16));
        if ($this->client instanceof \Redis) {
            $ok = $this->client->set($fenceKey, $token, ['PX' => 60_000]);
        } else {
            $ok = $this->client->setex($fenceKey, 60, $token);
        }
        if ($ok === false || $ok === null) {
            throw new ReplicaWaitException(sprintf('the replication fence write failed after %s', $what));
        }
    }

    /**
     * The verified WAIT itself: block until at least waitReplicas
     * replicas acknowledged the previous write, and fail closed when
     * they did not.
     *
     * Redis WAIT returns the number of replicas that processed the write
     * (0 on a replica-less server). The barrier asserts that number
     * against the configured threshold. With `waitReplicas > 0` the
     * durability promise is unconditional, so a lagging or unreachable
     * replica set raises {@see ReplicaWaitException} instead of silently
     * downgrading the guarantee; that failure is exactly the failover
     * replay window this barrier exists to close.
     */
    private function wait(string $what): void
    {
        if ($this->client instanceof \Redis) {
            // phpredis has no typed wait method; rawCommand sends the
            // command directly.
            $acked = $this->client->rawCommand('WAIT', $this->waitReplicas, $this->waitTimeoutMs);
        } else {
            // Predis removed the typed wait() method from its command
            // profile; executeRaw is the raw-command escape hatch (the same
            // semantics as phpredis rawCommand).
            $acked = $this->client->executeRaw(['WAIT', $this->waitReplicas, $this->waitTimeoutMs]);
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
     * Decode a stored JSON value back into a record, stripping the storage
     * runtime fields (`state`, `consumed_result`, `operation_identity`,
     * and the resume-claim fields `resume_owner` / `resume_until`) before
     * the strict serde-mirror parse; the canonical record schema never
     * sees them.
     *
     * Thin wrapper over the single-parse {@see self::decodeEnvelope()}
     * for callers that need only the record.
     *
     * @return ChallengeRecord|null null when the value is absent, not valid
     *                              JSON, not an object, or does not map to a
     *                              record (a corrupt key must not blow up the
     *                              verify path)
     */
    private function decode(string $raw): ?ChallengeRecord
    {
        return $this->decodeEnvelope($raw)['record'] ?? null;
    }

    /**
     * Decode the record AND the recorded logical-operation identity from
     * ONE json_decode of the same stored envelope bytes. The identity is
     * lifted before the runtime fields are stripped: `decode()` alone
     * unsets `operation_identity`, which the strict record parse must
     * never see. The identical source is therefore never parsed twice,
     * where the consume and retained-state paths used to pay a second
     * full json_decode per call just for the identity.
     *
     * @return array{record: ChallengeRecord, identity: string|null}|null
     *         null under the same contract as {@see self::decode()}
     */
    private function decodeEnvelope(string $raw): ?array
    {
        $this->envelopeDecodes++;
        try {
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($data)) {
            return null;
        }
        $identity = \is_string($data['operation_identity'] ?? null)
            ? $data['operation_identity']
            : null;
        unset($data['state'], $data['consumed_result'], $data['operation_identity'], $data['resume_owner'], $data['resume_until']);

        try {
            $record = ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return null;
        }

        return ['record' => $record, 'identity' => $identity];
    }

    /**
     * @internal Test seam: how many times the stored envelope bytes were
     * json_decode'd through {@see self::decodeEnvelope()} on this
     * storage instance. The single-parse contract of the consume and
     * retained-state paths asserts on it; production code never reads
     * it.
     */
    public function envelopeDecodeCount(): int
    {
        return $this->envelopeDecodes;
    }

    private function decodeResult(string $raw): ?ConsumedResult
    {
        try {
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($data)) {
            return null;
        }

        try {
            return ConsumedResult::fromArray($data);
        } catch (\Throwable) {
            return null;
        }
    }
}
