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
local v = redis.call("GET", KEYS[1])
if not v then
  return nil
end
local ok, obj = pcall(cjson.decode, v)
if not ok then
  return nil
end
local state = obj["state"] or "pending"
local consumedNow = 0
local consumedBefore = 0
if state == "consumed" then
  consumedBefore = 1
else
  obj["state"] = "consumed"
  local ttl = redis.call("TTL", KEYS[1])
  if ttl < 1 then ttl = 1 end
  redis.call("SET", KEYS[1], cjson.encode(obj), "EX", ttl)
  consumedNow = 1
end
local res = obj["consumed_result"]
if res == cjson.null then
  res = nil
end
return {v, consumedNow, consumedBefore, res ~= nil and cjson.encode(res) or ""}
LUA;

    /**
     * Atomic result commit: store {valid, binding} as `consumed_result` ONLY
     * when the record exists, is consumed, and has no result yet. Returns
     * 1 on success, 0 otherwise. ARGV = {valid "1"|"0", binding, has_binding
     * "1"|"0"}.
     */
    private const COMMIT_SCRIPT = <<<'LUA'
-- kiwicaptcha commit result (audit #74)
local v = redis.call("GET", KEYS[1])
if not v then
  return 0
end
local ok, obj = pcall(cjson.decode, v)
if not ok then
  return 0
end
if (obj["state"] or "pending") ~= "consumed" then
  return 0
end
local res = obj["consumed_result"]
if res ~= nil and res ~= cjson.null then
  return 0
end
local binding = ARGV[2]
if ARGV[3] == "0" then
  binding = cjson.null
end
obj["consumed_result"] = {valid = (ARGV[1] == "1"), binding = binding}
local ttl = redis.call("TTL", KEYS[1])
if ttl < 1 then ttl = 1 end
redis.call("SET", KEYS[1], cjson.encode(obj), "EX", ttl)
return 1
LUA;

    /**
     * @param int $waitReplicas   when > 0, store() issues a Redis WAIT after
     *                            SET so the record has reached this many
     *                            replicas before the challenge is handed to
     *                            the client (async-replication failover can
     *                            otherwise lose the record and replay it
     *                            after failback)
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
            $this->wait();
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

        // Lua tables are 1-indexed; normalize before destructuring.
        $parts = array_values($raw);
        if (\count($parts) < 4) {
            return null;
        }
        [$json, $consumedNow, $consumedBefore, $resultJson] = $parts;
        $record = $this->decode((string) $json);
        if ($record === null) {
            return null;
        }
        $result = ($resultJson === null || $resultJson === '') ? null : $this->decodeResult((string) $resultJson);

        return new ConsumedRecord($record, (bool) $consumedNow, (bool) $consumedBefore, $result);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::COMMIT_SCRIPT, [$key, $valid ? '1' : '0', $binding ?? '', $binding === null ? '0' : '1'], 1);

        return $raw === 1 || $raw === '1' || $raw === true;
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
     * write (the SET above). A replica-less or unreachable replica set
     * returns the number of acknowledged replicas (0) without error — WAIT
     * only bounds the blocking time; propagation success is NOT asserted.
     */
    private function wait(): void
    {
        if ($this->client instanceof \Redis) {
            // phpredis has no typed WAIT method; rawCommand mirrors the
            // GETDEL path.
            $this->client->rawCommand('WAIT', $this->waitReplicas, $this->waitTimeoutMs);
        } else {
            // Predis removed the typed wait() method from its command
            // profile; executeRaw is the raw-command escape hatch (the same
            // semantics as phpredis rawCommand).
            $this->client->executeRaw(['WAIT', $this->waitReplicas, $this->waitTimeoutMs]);
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
