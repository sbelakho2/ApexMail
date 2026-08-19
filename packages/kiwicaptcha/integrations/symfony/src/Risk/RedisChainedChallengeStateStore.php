<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;

/**
 * Redis-backed chained-challenge state store.
 *
 * Key: `{kiwi:<namespace>}:chain:<chainId>`
 * Value: JSON {stage1Nonce, scope, requestBinding, requiredAction,
 * policyVersion, chainDepth, state, owner, leaseUntil, stage2Nonce}
 * TTL: the chain lifetime (risk.chaining.ttl_secs).
 *
 * The chain lifecycle is a single-key Lua state machine (available ->
 * reserved(owner, leaseUntil) -> completed(stage2Nonce)): the reservation
 * is an OWNER-SCOPED lease (redis TIME reads the server clock; the lease
 * equals the record's OWN remaining TTL, preserved with KEEPTTL — the
 * signed ticket expiry is the true bound), the completion is a TERMINAL
 * state TRANSITION (never a delete — the completed record keeps its TTL
 * so a retry recovers the issued challenge), and the release is
 * owner-gated (a non-owner release is an atomic no-op — a failing request
 * can never free another owner's live reservation). Every script is
 * atomic even under concurrency, so a chain id is one-shot: exactly one
 * stage-2 issuance can ever win it, and a replayed ticket recovers the
 * issued challenge instead of re-minting.
 */
final class RedisChainedChallengeStateStore implements ChainedChallengeStateStore
{
    private const PREFIX = 'chain:';

    /**
     * Owner-scoped reservation lease: available -> reserved(me,
     * now + remaining TTL). The lease is computed from redis TIME + the
     * record's OWN remaining TTL (KEEPTTL preserves it — resetting would
     * only create stale state; the whole record expires with the signed
     * ticket anyway). reserved by ME -> 'retry'; reserved by another
     * owner with a live lease -> 'busy'; expired lease -> takeover; a
     * completed chain -> 'completed'.
     */
    private const RESERVE_LUA = <<<'LUA'
-- Chain reservation: owner-scoped lease (redis TIME for the lease).
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
local rec = cjson.decode(existing)
if rec['state'] == 'completed' then
  return 'completed'
end
if rec['state'] == 'reserved' then
  if rec['owner'] == ARGV[1] then
    return 'retry'
  end
  if tonumber(rec['leaseUntil']) > now then
    return 'busy'
  end
end
local remaining = tonumber(redis.call('TTL', KEYS[1]))
if remaining < 1 then
  remaining = tonumber(ARGV[2])
end
rec['state'] = 'reserved'
rec['owner'] = ARGV[1]
rec['leaseUntil'] = now + remaining
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'available'
LUA;

    /**
     * TERMINAL completion: reserved(me) -> completed(stage2Nonce) — a
     * state transition, NEVER a delete (the completed record keeps its
     * TTL so a retry recovers the issued challenge). Refused (atomic
     * no-op) for a non-owner or any state other than reserved. Returns
     * the completed record.
     */
    private const COMPLETE_LUA = <<<'LUA'
-- Chain completion: reserved(owner) -> completed(stage2Nonce).
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
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return cjson.encode(rec)
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

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwi',
    ) {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        // SET with the EX option array: the identical call shape on
        // phpredis and Predis.
        $this->redis->set(
            $this->key($chainId),
            (string) json_encode([
                'stage1Nonce' => $stage1Nonce,
                'scope' => $scope,
                'requestBinding' => $requestBinding,
                'requiredAction' => $requiredAction,
                'policyVersion' => $policyVersion,
                'chainDepth' => 2,
                'state' => 'available',
                'owner' => null,
                'leaseUntil' => null,
                'stage2Nonce' => null,
            ], JSON_THROW_ON_ERROR),
            ['EX' => max(1, $ttlSecs)],
        );
    }

    public function read(string $chainId): ?array
    {
        $raw = $this->redis->get($this->key($chainId));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $rec = self::decode($raw);
        if ($rec === null) {
            return null;
        }

        return self::wire($rec);
    }

    public function reserve(string $chainId, string $ownerToken, int $ttlSecs): string
    {
        $status = RedisEval::eval($this->redis, self::RESERVE_LUA, $this->key($chainId), [$ownerToken, (string) max(1, $ttlSecs)]);

        return \is_string($status) && \in_array($status, ['available', 'retry', 'busy', 'completed', 'missing'], true)
            ? $status
            : 'missing';
    }

    public function release(string $chainId, string $ownerToken): void
    {
        RedisEval::eval($this->redis, self::RELEASE_LUA, $this->key($chainId), [$ownerToken]);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        $raw = RedisEval::eval($this->redis, self::COMPLETE_LUA, $this->key($chainId), [$ownerToken, $stage2Nonce]);
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $rec = self::decode($raw);
        if ($rec === null) {
            return null;
        }

        return self::wire($rec);
    }

    private function key(string $chainId): string
    {
        return sprintf('{%s}:%s%s', $this->namespace, self::PREFIX, $chainId);
    }

    /** @return array<string, mixed>|null */
    private static function decode(string $raw): ?array
    {
        try {
            $rec = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return \is_array($rec) ? $rec : null;
    }

    /**
     * The wire shape of a record: the server-held fields with their
     * documented types (owner/leaseUntil/stage2Nonce null when unset).
     *
     * @param array<string, mixed> $rec
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string}
     */
    private static function wire(array $rec): array
    {
        return [
            'stage1Nonce' => \is_string($rec['stage1Nonce'] ?? null) ? $rec['stage1Nonce'] : '',
            'scope' => \is_string($rec['scope'] ?? null) ? $rec['scope'] : '',
            'requestBinding' => isset($rec['requestBinding']) && \is_string($rec['requestBinding']) ? $rec['requestBinding'] : null,
            'requiredAction' => \is_string($rec['requiredAction'] ?? null) ? $rec['requiredAction'] : '',
            'policyVersion' => \is_int($rec['policyVersion'] ?? null) ? $rec['policyVersion'] : 1,
            'chainDepth' => \is_int($rec['chainDepth'] ?? null) ? $rec['chainDepth'] : 2,
            'state' => \is_string($rec['state'] ?? null) ? $rec['state'] : 'available',
            'owner' => isset($rec['owner']) && \is_string($rec['owner']) ? $rec['owner'] : null,
            'leaseUntil' => isset($rec['leaseUntil']) && \is_int($rec['leaseUntil']) ? $rec['leaseUntil'] : null,
            'stage2Nonce' => isset($rec['stage2Nonce']) && \is_string($rec['stage2Nonce']) ? $rec['stage2Nonce'] : null,
        ];
    }
}
