<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Redis-backed NONCE-LEVEL redemption guard.
 *
 * Key: `{kiwi:<namespace>}:siteverify-redemption:<backend_id>:<nonce>`
 * Value: the response hash of the FIRST logical Siteverify operation for
 * the (backend, nonce) pair.
 * TTL: bounded (the caller passes the window).
 *
 * The registration is a single Lua script — atomic even under
 * concurrency — that SETs the value only when the key is absent
 * (SET NX) and returns the stored value, so the FIRST caller's hash
 * wins and every later caller observes the original. The guard
 * therefore records WHICH logical operation originally redeemed the
 * nonce, independent of any idempotency UUID: a takeover under a
 * DIFFERENT-UUID claim whose response hash differs from the original
 * redemption is a DIFFERENT logical operation and can never reconstruct
 * the original outcome.
 */
final class RedisSiteVerifyRedemptionGuard implements SiteVerifyRedemptionGuard
{
    private const PREFIX = 'siteverify-redemption:';

    private const REGISTER_LUA = <<<'LUA'
local key = KEYS[1]
local hash = ARGV[1]
local ttl = tonumber(ARGV[2])
redis.call('SET', key, hash, 'EX', ttl, 'NX')
return redis.call('GET', key)
LUA;

    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwicaptcha',
    ) {
    }

    public function register(string $backendId, string $nonce, string $responseHash, int $ttlSeconds): void
    {
        RedisEval::eval($this->redis, self::REGISTER_LUA, $this->key($backendId, $nonce), [$responseHash, max(1, $ttlSeconds)]);
    }

    public function originalHash(string $backendId, string $nonce): ?string
    {
        $raw = $this->redis->get($this->key($backendId, $nonce));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return $raw;
    }

    private function key(string $backendId, string $nonce): string
    {
        return sprintf('{%s}:%s%s:%s', $this->namespace, self::PREFIX, $backendId, $nonce);
    }
}
