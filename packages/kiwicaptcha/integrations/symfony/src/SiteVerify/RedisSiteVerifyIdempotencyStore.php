<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Redis-backed atomic idempotency store (round 30 P1).
 *
 * Key: `{kiwi:<namespace>}:siteverify-idem:<backend_id>:<uuid>`
 * Value: JSON {response_hash, state: pending|complete, owner, result}
 * TTL: bounded (the caller passes the window).
 *
 * The claim is a single Lua script — atomic even under concurrency.
 * `owner` is a random per-request token so only the owning request can
 * finalize (a stale retry can never overwrite a completed outcome).
 */
final class RedisSiteVerifyIdempotencyStore implements SiteVerifyIdempotencyStore
{
    private const PREFIX = 'siteverify-idem:';

    private const CLAIM_LUA = <<<'LUA'
local key = KEYS[1]
local response_hash = ARGV[1]
local owner = ARGV[2]
local ttl = tonumber(ARGV[3])
local existing = redis.call('GET', key)
if not existing then
  redis.call('SET', key, cjson.encode({ response_hash = response_hash, state = 'pending', owner = owner, result = cjson.null }), 'EX', ttl)
  return 'claimed'
end
local rec = cjson.decode(existing)
if rec.response_hash ~= response_hash then
  return 'conflict'
end
if rec.state == 'complete' then
  return 'complete_same'
end
return 'pending_same'
LUA;

    private const FINALIZE_LUA = <<<'LUA'
local key = KEYS[1]
local owner = ARGV[1]
local result = ARGV[2]
local ttl = tonumber(ARGV[3])
local existing = redis.call('GET', key)
if not existing then
  return 0
end
local rec = cjson.decode(existing)
if rec.owner ~= owner then
  return 0
end
rec.state = 'complete'
rec.result = cjson.decode(result)
redis.call('SET', key, cjson.encode(rec), 'EX', ttl)
return 1
LUA;

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwicaptcha',
    ) {
    }

    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds): array
    {
        $owner = bin2hex(random_bytes(16));
        $result = $this->redis instanceof \Redis
            ? $this->redis->eval(self::CLAIM_LUA, [$this->key($backendId, $idempotencyKey)], 1, $responseHash, $owner, max(1, $ttlSeconds))
            : $this->redis->eval(self::CLAIM_LUA, 1, $this->key($backendId, $idempotencyKey), $responseHash, $owner, max(1, $ttlSeconds));

        $claim = match ((string) $result) {
            'claimed' => IdempotencyClaim::Claimed,
            'pending_same' => IdempotencyClaim::PendingSame,
            'complete_same' => IdempotencyClaim::CompleteSame,
            default => IdempotencyClaim::Conflict,
        };

        return [$claim, $claim === IdempotencyClaim::Claimed ? $owner : null];
    }

    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
    {
        $payload = (string) json_encode($canonicalResponse, JSON_THROW_ON_ERROR);
        $result = $this->redis instanceof \Redis
            ? $this->redis->eval(self::FINALIZE_LUA, [$this->key($backendId, $idempotencyKey)], 1, $owner, $payload, max(1, $this->finalizeTtl($idempotencyKey)))
            : $this->redis->eval(self::FINALIZE_LUA, 1, $this->key($backendId, $idempotencyKey), $owner, $payload, max(1, $this->finalizeTtl($idempotencyKey)));
        // The owning request's finalize is authoritative; a failed Lua
        // (lost key / foreign owner) is a no-op — the entry expires on TTL.
        unset($result);
    }

    public function stored(string $backendId, string $idempotencyKey): ?array
    {
        $raw = $this->redis->get($this->key($backendId, $idempotencyKey));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        try {
            $rec = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($rec) || ($rec['state'] ?? '') !== 'complete' || !\is_array($rec['result'] ?? null)) {
            return null;
        }

        return $rec['result'];
    }

    private function finalizeTtl(string $idempotencyKey): int
    {
        // finalize does not know the original TTL; keep a conservative
        // bounded window so completed entries are readable for retries.
        return 300;
    }

    private function key(string $backendId, string $idempotencyKey): string
    {
        return sprintf('{%s}:%s%s:%s', $this->namespace, self::PREFIX, $backendId, $idempotencyKey);
    }
}
