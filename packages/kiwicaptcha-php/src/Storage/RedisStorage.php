<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;

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
 * - phpredis (\Redis): eval() with the script.
 * - Predis: eval() (the same script; the server must support Lua, i.e.
 *   any Redis >= 2.6).
 *
 * Records are stored as JSON in the canonical `ChallengeRecord` wire
 * keys schema, which is language-neutral: a Rust service using the same
 * Redis instance can read them and vice versa. The JSON is wrapped with
 * the three runtime fields `state` ("pending"|"consumed"),
 * `consumed_result` (null | {valid, binding}) and `operation_identity`
 * (null | a bounded <= 128-byte logical-operation identity recorded
 * atomically with the pending→consumed transition via
 * {@see OperationIdentityAwareStorageInterface}). The runtime fields are
 * storage-layer additions after the canonical parse: `decode()` strips
 * them before {@see ChallengeRecord::fromArray()} so the strict
 * serde-mirror parser never sees them. That preserves deny_unknown_fields
 * parity with the Rust reader, which strips them the same way. The
 * record's TTL is the key expiration; the consume transition preserves
 * it.
 *
 * Implements {@see \KiwiCaptcha\AtomicStorageInterface}: the fused
 * read-transition makes consume() strict single-use under concurrency.
 */
final class RedisStorage implements AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, \KiwiCaptcha\AtomicDeleteIfPendingInterface
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
  local ttl = redis.call("TTL", KEYS[1])
  if ttl < 1 then ttl = 1 end
  local updated, n = string.gsub(v, '"state":"pending"', '"state":"consumed"', 1)
  if n ~= 1 then
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
-- notation). A consumed record is returned verbatim and kept; only a
-- pending record is deleted.
--
-- The DEL is a durability-critical write: the caller applies the same
-- verified WAIT barrier as the other transitions, so a burned challenge
-- that only vanished from the primary can never be resurrected as
-- pending by a promoted stale replica.
local v = redis.call("GET", KEYS[1])
if not v then
  return {'missing'}
end
if string.find(v, '"state":"consumed"', 1, true) then
  return {'consumed', v}
end
redis.call("DEL", KEYS[1])
return {'deleted-pending'}
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
local encoded = cjson.encode({
  valid = (ARGV[1] == '1'),
  binding = (ARGV[3] == "0") and cjson.null or ARGV[2]
})
local updated, n = string.gsub(v, '"consumed_result":null', '"consumed_result":' .. encoded, 1)
if n ~= 1 then
  return 0
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
    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        if ($this->waitReplicas <= 0 || !($this->client instanceof \Predis\Client)) {
            return;
        }
        $connection = $this->client->getConnection();
        if ($connection instanceof \Predis\Connection\Replication\ReplicationInterface) {
            throw new \InvalidArgumentException(
                'RedisStorage: verified-WAIT durability (waitReplicas > 0) is not supported on a Predis replication aggregate (Sentinel or master-slave) — WAIT is connection-affine, counting replicas of the connection it is sent on, and the aggregate\'s failure retry executes the WAIT on a replacement connection whose write offset is empty, so the acknowledgement proves nothing about the original write\'s replication. The verified barrier supports standalone Redis connections only; use a standalone connection with waitReplicas > 0, or keep waitReplicas = 0 on an aggregate.'
            );
        }
        if ($connection instanceof \Predis\Connection\Cluster\ClusterInterface) {
            throw new \InvalidArgumentException(
                'RedisStorage: verified-WAIT durability (waitReplicas > 0) is not supported on a Predis Redis Cluster client — WAIT is connection-relative and cannot be routed by slot. The verified barrier supports standalone Redis connections only; use a standalone connection with waitReplicas > 0, or keep waitReplicas = 0 on a cluster.'
            );
        }
        if ($connection === null) {
            // An in-memory stand-in with no real connection object (the
            // tests' FakePredisClient skips the parent constructor): there
            // is no Parameters instance to carry a retry policy and the
            // stand-in overrides the command dispatch itself, so the
            // vendored retry wrapper never engages.
            return;
        }
        if ($connection instanceof \Predis\Connection\RelayConnection) {
            // A relay connection dispatches commands directly, bypassing
            // the vendored retry wrapper (Predis\Client::executeCommand
            // excludes relay connections), so an explicit retry parameter
            // is inert there and cannot replay a mutation.
            return;
        }
        if (!$connection->getParameters()->isDisabledRetry()) {
            throw new \InvalidArgumentException(
                'RedisStorage: verified-WAIT durability (waitReplicas > 0) is not supported on a retry-enabled standalone Predis client — verified-WAIT durability requires that a durability-critical mutation is attempted exactly once on the connection whose subsequent WAIT establishes the replication offset, and a retry-enabled standalone Predis client can transparently re-execute the Lua mutation after a lost response, so the returned result may describe the second invocation rather than the one that mutated: a delete-if-pending eval whose first execution performed the terminal DEL is retried into a \'missing\' reply, and the verified WAIT that must follow the mutation is skipped, leaving a burned challenge resurrectable. Retries must be disabled on the connection (remove the \'retry\' connection parameter), or keep waitReplicas = 0.'
            );
        }
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
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::CONSUME_SCRIPT, [$key, ''], 1);
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

        $record = $this->decode((string) $json);
        if ($record === null) {
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

        return new ConsumedRecord($record, (bool) $consumedNow, (bool) $consumedBefore, $result, $this->decodeIdentity((string) $json));
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
        $key = $this->prefix.$nonce;
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

        $record = $this->decode((string) $json);
        if ($record === null) {
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

        return new ConsumedRecord($record, (bool) $consumedNow, (bool) $consumedBefore, $result, $this->decodeIdentity((string) $json));
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || $raw === '' || !str_contains($raw, '"state":"consumed"')) {
            return null;
        }
        $record = $this->decode($raw);
        if ($record === null) {
            return null;
        }
        $result = null;
        $resultJson = self::extractConsumedResultJson($raw);
        if ($resultJson !== null) {
            $result = $this->decodeResult($resultJson);
        }

        return new ConsumedRecord($record, false, true, $result, $this->decodeIdentity($raw));
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
     * deleted-pending / consumed (the same tri-state contract as
     * {@see \KiwiCaptcha\AtomicDeleteIfPendingInterface}).
     *
     * The deleted-pending transition is durability-critical and carries
     * the same verified WAIT contract as issuance, the pending-to-consumed
     * transition and the result commit. The delete must reach the
     * configured replica count before the caller may treat the challenge
     * as burned, or a promoted stale replica could resurrect it as
     * pending and let it be redeemed. A violated barrier surfaces the
     * same fail-closed {@see ReplicaWaitException} as the other
     * transitions. No WAIT is issued for missing or consumed, since no
     * mutation occurred.
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
        // consumed: decode the retained envelope from the returned bytes
        // (the committed result and the recorded operation identity ride
        // along — no second lookup). No WAIT: no mutation occurred, the
        // record was already durably consumed.
        $json = (string) ($parts[1] ?? '');
        $record = $this->decode($json);
        if ($record === null) {
            throw new \RuntimeException('delete-if-pending: undecodable consumed envelope');
        }
        $result = null;
        $resultJson = self::extractConsumedResultJson($json);
        if ($resultJson !== null) {
            $result = $this->decodeResult($resultJson);
        }

        return new \KiwiCaptcha\DeleteIfPendingResult('consumed', new ConsumedRecord($record, false, true, $result, $this->decodeIdentity($json)));
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

    public function delete(string $nonce): void
    {
        $this->client->del($this->prefix.$nonce);
    }

    /**
     * @param list<mixed> $args    key(s) then script arguments
     * @param int         $numKeys number of leading keys in $args
     */
    private function evalScript(string $script, array $args, int $numKeys): mixed
    {
        if ($this->client instanceof \Redis) {
            return $this->client->eval($script, $args, $numKeys);
        }

        return $this->client->eval($script, $numKeys, ...$args);
    }

    /**
     * Block until at least waitReplicas replicas acknowledged the previous
     * write, and fail closed when they did not.
     *
     * Redis WAIT returns the number of replicas that processed the write
     * (0 on a replica-less server). The barrier asserts that number
     * against the configured threshold. With `waitReplicas > 0` the
     * durability promise is unconditional, so a lagging or unreachable
     * replica set raises {@see ReplicaWaitException} instead of silently
     * downgrading the guarantee; that failure is exactly the failover
     * replay window this barrier exists to close.
     */
    private function waitAndVerify(string $what): void
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
     * runtime fields (`state`, `consumed_result`, `operation_identity`)
     * before the strict serde-mirror parse; the canonical record schema
     * never sees them.
     *
     * @return ChallengeRecord|null null when the value is absent, not valid
     *                              JSON, not an object, or does not map to a
     *                              record (a corrupt key must not blow up the
     *                              verify path)
     */
    private function decode(string $raw): ?ChallengeRecord
    {
        try {
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($data)) {
            return null;
        }
        unset($data['state'], $data['consumed_result'], $data['operation_identity']);

        try {
            return ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The logical-operation identity recorded on a stored value, or null
     * when the record carries none (a plain consume, an identity-less
     * record, or a non-string marker from an older/foreign writer).
     */
    private function decodeIdentity(string $raw): ?string
    {
        try {
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($data) || !\is_string($data['operation_identity'] ?? null)) {
            return null;
        }

        return $data['operation_identity'];
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
