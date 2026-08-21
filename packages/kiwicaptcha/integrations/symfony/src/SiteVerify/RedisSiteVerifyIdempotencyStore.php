<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * Redis-backed atomic idempotency store.
 *
 * Key: `{kiwi:<namespace>}:siteverify-idem:<backend_id>:<uuid>`
 * Value: JSON {response_hash, remoteip_fingerprint, state:
 * pending|complete, owner, result, lease_expires_at}
 * TTL: bounded (the caller passes the window).
 *
 * The claim is a single Lua script — atomic even under concurrency.
 * `owner` is a random per-request token so only the owning request can
 * finalize (a stale retry can never overwrite a completed outcome). The
 * claim binds the canonicalized remoteip fingerprint alongside the
 * response hash. A retry with the same key but a different fingerprint
 * is a conflict: a changed remoteip can materially change the
 * verification outcome, and no entry may be joined or reused across
 * fingerprints. Records written without a fingerprint (created by an
 * older release) carry none and therefore conflict with every claim,
 * fail-closed, and expire on TTL. The owner's lease
 * (`lease_expires_at`, set from the server clock via redis TIME at
 * claim creation) is configurable (`leaseSeconds`, default
 * {@see SiteVerifyIdempotencyStore::LEASE_SECONDS}) and bounds how long
 * a crashed owner blocks the key. After expiry an atomic takeover
 * transfers ownership to a waiter, and the lease length itself (not any
 * process-global timer) protects a live owner mid-verification.
 */
final class RedisSiteVerifyIdempotencyStore implements SiteVerifyIdempotencyStore
{
    private const PREFIX = 'siteverify-idem:';

    private const CLAIM_LUA = <<<'LUA'
local key = KEYS[1]
local response_hash = ARGV[1]
local owner = ARGV[2]
local ttl = tonumber(ARGV[3])
local lease_seconds = tonumber(ARGV[4])
local fingerprint = ARGV[5]
-- redis TIME returns bulk strings; tonumber makes the arithmetic explicit.
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', key)
if not existing then
  redis.call('SET', key, cjson.encode({ response_hash = response_hash, remoteip_fingerprint = fingerprint, state = 'pending', owner = owner, result = cjson.null, lease_expires_at = now + lease_seconds }), 'EX', ttl)
  return 'claimed'
end
local rec = cjson.decode(existing)
if rec.response_hash ~= response_hash or rec.remoteip_fingerprint ~= fingerprint then
  return 'conflict'
end
if rec.state == 'complete' then
  return 'complete_same'
end
return 'pending_same'
LUA;

    private const TAKEOVER_LUA = <<<'LUA'
local key = KEYS[1]
local owner = ARGV[1]
local response_hash = ARGV[2]
local fingerprint = ARGV[3]
local lease_seconds = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', key)
if not existing then
  return 'still_pending'
end
local rec = cjson.decode(existing)
if rec.state ~= 'pending' then
  return 'still_pending'
end
if rec.response_hash ~= response_hash then
  return 'still_pending'
end
-- The remoteip fingerprint is bound in the record: a takeover with a
-- DIFFERENT fingerprint is refused (defense-in-depth — the claim
-- already enforces it, but the store enforces the complete identity
-- itself). A legacy record without a fingerprint matches nothing
-- (fail-closed), exactly like the claim.
if rec.remoteip_fingerprint ~= fingerprint then
  return 'still_pending'
end
-- A legacy record without a lease field is treated as already expired.
local lease_expires_at = tonumber(rec.lease_expires_at) or 0
if lease_expires_at >= now then
  return 'still_pending'
end
rec.owner = owner
rec.lease_expires_at = now + lease_seconds
redis.call('SET', key, cjson.encode(rec), 'EX', ttl)
return 'took_over'
LUA;

    private const RENEW_LUA = <<<'LUA'
local key = KEYS[1]
local owner = ARGV[1]
local lease_seconds = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', key)
if not existing then
  return 0
end
local rec = cjson.decode(existing)
if rec.state ~= 'pending' or rec.owner ~= owner then
  return 0
end
rec.lease_expires_at = now + lease_seconds
redis.call('SET', key, cjson.encode(rec), 'EX', ttl)
return 1
LUA;

    private const FINALIZE_LUA = <<<'LUA'
local key = KEYS[1]
local owner = ARGV[1]
local response_hash = ARGV[2]
local result = ARGV[3]
local ttl = tonumber(ARGV[4])
local existing = redis.call('GET', key)
if not existing then
  return 0
end
local rec = cjson.decode(existing)
-- The finalize must authorize BOTH the current owner token AND the
-- response hash bound in the record: a finalize with the right owner
-- but the WRONG hash is an atomic no-op.
if rec.owner ~= owner or rec.response_hash ~= response_hash then
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
        private readonly int $leaseSeconds = self::LEASE_SECONDS,
    ) {
    }

    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
    {
        $owner = bin2hex(random_bytes(16));
        $lease = $leaseSeconds ?? $this->leaseSeconds;
        $result = RedisEval::eval($this->redis, self::CLAIM_LUA, $this->key($backendId, $idempotencyKey), [$responseHash, $owner, max(1, $ttlSeconds), $lease, $remoteipFingerprint]);

        $claim = match ((string) $result) {
            'claimed' => IdempotencyClaim::Claimed,
            'pending_same' => IdempotencyClaim::PendingSame,
            'complete_same' => IdempotencyClaim::CompleteSame,
            default => IdempotencyClaim::Conflict,
        };

        return [$claim, $claim === IdempotencyClaim::Claimed ? $owner : null];
    }

    public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null): array
    {
        $owner = bin2hex(random_bytes(16));
        // The takeover Lua already receives the lease via ARGV[4]; pass
        // the per-call override so the fixed configured lease is
        // maintained across the takeover (null = the configured lease —
        // the controller always passes null; the lease is never derived
        // from a token's remaining validity).
        $result = RedisEval::eval($this->redis, self::TAKEOVER_LUA, $this->key($backendId, $idempotencyKey), [$owner, $responseHash, $remoteipFingerprint, $leaseSeconds ?? $this->leaseSeconds, max(1, $ttlSeconds)]);

        $takeover = match ((string) $result) {
            'took_over' => IdempotencyClaim::TookOver,
            default => IdempotencyClaim::StillPending,
        };

        return [$takeover, $takeover === IdempotencyClaim::TookOver ? $owner : null];
    }

    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
    {
        $payload = (string) json_encode($canonicalResponse, JSON_THROW_ON_ERROR);
        $result = RedisEval::eval($this->redis, self::FINALIZE_LUA, $this->key($backendId, $idempotencyKey), [$owner, $responseHash, $payload, max(1, $this->retentionTtl($idempotencyKey))]);
        // The owning request's finalize is authoritative; a failed Lua
        // (lost key / foreign owner) is a no-op — the entry expires on TTL.
        unset($result);
    }

    public function renew(string $backendId, string $idempotencyKey, string $owner): bool
    {
        $result = RedisEval::eval($this->redis, self::RENEW_LUA, $this->key($backendId, $idempotencyKey), [$owner, $this->leaseSeconds, max(1, $this->retentionTtl($idempotencyKey))]);

        return (string) $result === '1';
    }

    public function leaseSeconds(): int
    {
        return $this->leaseSeconds;
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

    private function retentionTtl(string $idempotencyKey): int
    {
        // finalize and renew do not know the original TTL; keep a
        // conservative bounded window so completed entries are readable for
        // retries.
        return 300;
    }

    private function key(string $backendId, string $idempotencyKey): string
    {
        return sprintf('{%s}:%s%s:%s', $this->namespace, self::PREFIX, $backendId, $idempotencyKey);
    }
}
