<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;

/**
 * Redis-backed storage with TRUE atomic one-shot semantics.
 *
 * `consume()` is a TRANSITION (audit #74), not a delete: an atomic Lua
 * script marks the record consumed and KEEPS it until its TTL. Replay
 * protection is the consumed marker, not absence — and the record can carry
 * a deterministic verification result (`consumed_result`) so a retry on an
 * already-consumed record returns the SAME outcome without re-deriving.
 * `commitResult()` stores that result atomically (only when the record is
 * consumed and has no result yet). Two concurrent consumers race inside a
 * single eval: Redis serializes the script, so exactly one caller wins
 * `consumedNow` — strict single-use under concurrency.
 *
 * - phpredis (\Redis): eval() with the script.
 * - Predis: eval() (the same script; the server must support Lua, i.e. any
 *   Redis >= 2.6).
 *
 * Records are stored as JSON: the canonical 21-key `ChallengeRecord` schema
 * (LANGUAGE-NEUTRAL — a Rust service using the same Redis instance can read
 * them, and vice versa) WRAPPED with the two runtime fields `state`
 * ("pending"|"consumed") and `consumed_result` (null | {valid, binding}).
 * The runtime fields are storage-layer additions AFTER the canonical parse:
 * `decode()` strips them before {@see ChallengeRecord::fromArray()} so the
 * strict serde-mirror parser never sees them (deny_unknown_fields parity
 * with the Rust reader, which strips them the same way). The record's TTL is
 * the key expiration; the consume transition preserves it.
 *
 * Implements {@see \KiwiCaptcha\AtomicStorageInterface}: the fused
 * read-transition makes consume() strict single-use under concurrency.
 */
final class RedisStorage implements AtomicStorageInterface
{
    /**
     * Atomic consume transition: GET the record; if present and not yet
     * consumed, flip `state` to "consumed" (preserving the key TTL). Returns
     * nil for a missing record, else {json, consumed_now, consumed_before,
     * consumed_result_json} — the result is the committed JSON (""
     * when absent).
     */
    private const CONSUME_SCRIPT = <<<'LUA'
-- kiwicaptcha consume transition (audit #74)
--
-- CRITICAL: the record is NEVER re-encoded through cjson — re-encoding
-- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
-- and breaks both strict parsers. The state field is spliced into the
-- RAW stored JSON string (store() always writes the exact
-- `"state":"pending"` marker).
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
  redis.call("SET", KEYS[1], updated, "EX", ttl)
  consumedNow = 1
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
     * Atomic result commit: store {valid, binding} as `consumed_result` ONLY
     * when the record exists, is consumed, and has no result yet. Returns
     * 1 on success, 0 otherwise. ARGV = {valid "1"|"0", binding, has_binding
     * "1"|"0"}.
     */
    private const COMMIT_SCRIPT = <<<'LUA'
-- kiwicaptcha commit result (audit #74)
--
-- Same raw-splice rule as CONSUME_SCRIPT: the stored JSON is never
-- re-encoded through cjson (large integers would switch to scientific
-- notation). The `"consumed_result":null` marker written by store() is
-- replaced in place; the binding is embedded as a JSON string.
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
local binding = cjson.encode(ARGV[2])
if ARGV[3] == "0" then
  binding = 'null'
end
local encoded = '{"valid":' .. ARGV[1] .. ',"binding":' .. binding .. '}'
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
     * @param int $waitReplicas   when > 0, every durability-critical write
     *                            (issuance SET, the pending→consumed
     *                            transition, the result commit) is followed
     *                            by a Redis WAIT whose acknowledgement count
     *                            is VERIFIED: fewer than waitReplicas acked
     *                            replicas raises {@see ReplicaWaitException}
     *                            (fail closed — the guarantee is
     *                            unconditional, never silently downgraded).
     *                            Async-replication failover can otherwise
     *                            lose a write or resurrect a consumed
     *                            record from a stale replica
     * @param int $waitTimeoutMs  WAIT timeout in milliseconds (default 100)
     * @param int $ttlMarginSecs  extra retention on the record beyond token
     *                            validity: TTL = expires_at - now + margin
     *                            (must exceed max clock skew + failover
     *                            margin so a replayed token can never land on
     *                            an already-expired state)
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly string $prefix = 'kiwicaptcha:',
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
        private readonly int $ttlMarginSecs = 0,
    ) {
    }

    public function store(ChallengeRecord $record): void
    {
        $key = $this->prefix.$record->nonce;
        $value = json_encode(
            $record->toArray() + ['state' => 'pending', 'consumed_result' => null],
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

    public function consume(string $nonce): ?ConsumedRecord
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::CONSUME_SCRIPT, [$key], 1);
        if ($raw === false || $raw === null || !\is_array($raw)) {
            return null;
        }

        // Durability barrier (audit round 14): the pending→consumed
        // transition must reach the configured replica count before the
        // caller is allowed to treat the record as consumed. QUALIFICATION
        // (audit round 22 — same wording as SECURITY.md): WAIT N proves
        // that at least N replicas acknowledged the write; it does NOT
        // constrain which replicas a future failover manager promotes —
        // replay-safe promotion additionally requires the threshold to
        // cover every eligible failover target or promotion gating.
        if ($this->waitReplicas > 0) {
            $this->waitAndVerify('the pending→consumed transition');
        }

        // Lua tables are 1-indexed; normalize before destructuring.
        $parts = array_values($raw);
        if (\count($parts) < 4) {
            return null;
        }
        [$json, $consumedNow, $consumedBefore, $resultBinding] = $parts;
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

        return new ConsumedRecord($record, (bool) $consumedNow, (bool) $consumedBefore, $result);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::COMMIT_SCRIPT, [$key, $valid ? '1' : '0', $binding ?? '', $binding === null ? '0' : '1'], 1);
        $committed = $raw === 1 || $raw === '1' || $raw === true;

        // Durability barrier (audit round 14): a committed deterministic
        // result that only lives on the primary would be lost on promotion,
        // degrading a retry to ConsumeIndeterminate. The barrier keeps the
        // commit's durability contract honest. Callers treat commit as
        // best-effort, so a barrier failure cannot change the outcome — it
        // only surfaces the (safe) degraded state on the next retry.
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
     * write, and FAIL CLOSED when they did not (audit round 14).
     *
     * Redis WAIT returns the number of replicas that processed the write
     * (0 on a replica-less server). The barrier asserts that number against
     * the configured threshold: with `waitReplicas > 0` the durability
     * promise is unconditional, so a lagging/unreachable replica set raises
     * {@see ReplicaWaitException} instead of silently downgrading the
     * guarantee — exactly the failure the failover replay window relied on.
     */
    private function waitAndVerify(string $what): void
    {
        if ($this->client instanceof \Redis) {
            // phpredis has no typed WAIT method; rawCommand mirrors the
            // GETDEL path.
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
     * runtime fields (`state`, `consumed_result`) BEFORE the strict
     * serde-mirror parse — the canonical record schema never sees them.
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
        unset($data['state'], $data['consumed_result']);

        try {
            return ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return null;
        }
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
