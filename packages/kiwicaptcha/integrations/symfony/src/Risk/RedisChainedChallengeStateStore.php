<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;

/**
 * Redis-backed chained-challenge state store.
 *
 * Key: `{kiwi:<namespace>}:chain:<chainId>`
 * Value: JSON {stage1Nonce, scope}
 * TTL: the chain lifetime (risk.chaining.ttl_secs).
 *
 * The consume is a single Lua script (GET + DEL) — atomic even under
 * concurrency, so a chain id is one-shot: exactly one stage-2 issuance
 * can ever win it, and a replayed ticket is refused.
 */
final class RedisChainedChallengeStateStore implements ChainedChallengeStateStore
{
    private const PREFIX = 'chain:';

    private const CONSUME_LUA = <<<'LUA'
local key = KEYS[1]
local existing = redis.call('GET', key)
if not existing then
  return false
end
redis.call('DEL', key)
return existing
LUA;

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwi',
    ) {
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs): void
    {
        $this->redis->setex(
            $this->key($chainId),
            max(1, $ttlSecs),
            (string) json_encode(['stage1Nonce' => $stage1Nonce, 'scope' => $scope], JSON_THROW_ON_ERROR),
        );
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

        return ['stage1Nonce' => $rec['stage1Nonce'], 'scope' => $rec['scope']];
    }

    private function key(string $chainId): string
    {
        return sprintf('{%s}:%s%s', $this->namespace, self::PREFIX, $chainId);
    }
}
