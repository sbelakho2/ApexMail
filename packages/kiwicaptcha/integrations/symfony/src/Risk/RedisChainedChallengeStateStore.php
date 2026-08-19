<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;

/**
 * Redis-backed chained-challenge state store.
 *
 * Key: `{kiwi:<namespace>}:chain:<chainId>`
 * Value: JSON {stage1Nonce, scope, requestBinding, requiredAction, state}
 * TTL: the chain lifetime (risk.chaining.ttl_secs).
 *
 * The chain lifecycle is a single-key Lua state machine (available ->
 * reserved -> consumed): the reservation transition is ATOMIC and
 * idempotent for the same chain id (a retry re-enters the reserved state
 * and re-attempts issuance), the consume is a one-shot GET + DEL (a chain
 * id is spent exactly when the stage-2 issuance is durably complete), and
 * the release undoes a reservation so a refused or failed issuance never
 * burns the ticket. Every script is atomic even under concurrency, so a
 * chain id is one-shot: exactly one stage-2 issuance can ever win it, and
 * a replayed ticket is refused.
 */
final class RedisChainedChallengeStateStore implements ChainedChallengeStateStore
{
    private const PREFIX = 'chain:';

    /**
     * Reservation: available -> reserved (idempotent for the same chain
     * id; a retry re-enters reserved and re-attempts issuance). The
     * reservation inherits the chain TTL (re-applied on the first
     * transition so the state change never loses the key's lifetime —
     * the ticket's signed expiry stays the authoritative bound).
     */
    private const RESERVE_LUA = <<<'LUA'
local existing = redis.call('GET', KEYS[1])
if not existing then
  return 'missing'
end
local rec = cjson.decode(existing)
if rec['state'] == 'consumed' then
  return 'consumed'
end
if rec['state'] == 'reserved' then
  return 'reserved'
end
rec['state'] = 'reserved'
redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', tonumber(ARGV[1]))
return 'available'
LUA;

    /**
     * One-shot completion: GET + DEL in one script — at most ONE consumer
     * ever wins a chain id, and only the reserved/available state can be
     * consumed (a consumed chain id is gone, never re-gated).
     */
    private const CONSUME_LUA = <<<'LUA'
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
redis.call('DEL', KEYS[1])
return existing
LUA;

    /**
     * Release: reserved -> available (the reservation holder's retry
     * path — a refused or failed issuance must not burn the ticket). The
     * chain TTL is preserved (KEEPTTL, Redis 6.0+).
     */
    private const RELEASE_LUA = <<<'LUA'
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
local rec = cjson.decode(existing)
if rec['state'] == 'consumed' then
  return false
end
rec['state'] = 'available'
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return true
LUA;

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwi',
    ) {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null): void
    {
        $this->redis->setex(
            $this->key($chainId),
            max(1, $ttlSecs),
            (string) json_encode([
                'stage1Nonce' => $stage1Nonce,
                'scope' => $scope,
                'requestBinding' => $requestBinding,
                'requiredAction' => $requiredAction,
                'state' => 'available',
            ], JSON_THROW_ON_ERROR),
        );
    }

    public function reserve(string $chainId, int $ttlSecs): string
    {
        $status = RedisEval::eval($this->redis, self::RESERVE_LUA, $this->key($chainId), [(string) max(1, $ttlSecs)]);

        return \is_string($status) && \in_array($status, ['available', 'reserved', 'consumed', 'missing'], true)
            ? $status
            : 'missing';
    }

    public function consume(string $chainId): ?array
    {
        $raw = RedisEval::eval($this->redis, self::CONSUME_LUA, $this->key($chainId), []);
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        try {
            $rec = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($rec) || !\is_string($rec['stage1Nonce'] ?? null) || !\is_string($rec['scope'] ?? null)) {
            return null;
        }

        return [
            'stage1Nonce' => $rec['stage1Nonce'],
            'scope' => $rec['scope'],
            'requestBinding' => isset($rec['requestBinding']) && \is_string($rec['requestBinding']) ? $rec['requestBinding'] : null,
            'requiredAction' => isset($rec['requiredAction']) && \is_string($rec['requiredAction']) ? $rec['requiredAction'] : null,
        ];
    }

    public function release(string $chainId): void
    {
        RedisEval::eval($this->redis, self::RELEASE_LUA, $this->key($chainId), []);
    }

    private function key(string $chainId): string
    {
        return sprintf('{%s}:%s%s', $this->namespace, self::PREFIX, $chainId);
    }
}
