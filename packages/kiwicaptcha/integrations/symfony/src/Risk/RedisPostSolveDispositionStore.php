<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisEval;

/**
 * Redis-backed durable post-solve disposition store.
 *
 * Key: `{kiwi:<namespace>}:postsolve:<nonce>` (the nonce is random
 * security state — no HMAC). Value: JSON
 *   pending:  {"v":1,"state":"pending","owner":...,"lease_until":...,"disposition":null}
 *   complete: {"v":1,"state":"complete","owner":null,"lease_until":null,
 *              "disposition":{"kind":"chain_required","decision_id":...,"chain_id":...}}
 * Record TTL: the constructor's configured TTL (the extension wires
 * Config::MAX_TTL_SECS + risk.redis.ttl_margin_secs) — the disposition
 * survives at least as long as the consumed core result can be replayed;
 * the per-call claim TTL applies when no configured TTL is given.
 *
 * The claim is ONE atomic Lua state machine (missing -> pending(me,
 * lease); pending+me -> 'pending'; pending+other+live -> 'pending' (busy);
 * pending+other+expired -> takeover -> 'taken_over'; complete ->
 * 'complete'): at most one owner computes a nonce's disposition. The
 * SHORT FIXED lease (15 s) bounds the in-flight window — never the record
 * TTL. The finalize is atomic too: pending(me) -> complete, refused for a
 * non-owner or a non-pending record, so a crash-taken-over computation
 * can never overwrite a completed disposition and a replayed proof
 * reproduces the persisted final disposition.
 */
final class RedisPostSolveDispositionStore implements PostSolveDispositionStore
{
    private const PREFIX = 'postsolve:';

    /** The SHORT FIXED computation lease — a contention bound, never the record TTL. */
    private const LEASE_SECS = 15;

    /**
     * Single-Lua claim: one atomic transition per nonce.
     *   KEYS[1] = {kiwi:<ns>}:postsolve:<nonce>
     *   ARGV[1] = owner token, ARGV[2] = lease seconds, ARGV[3] = record TTL
     * Returns 'claimed' | 'pending' | 'taken_over' | 'complete'.
     */
    private const CLAIM_LUA = <<<'LUA'
-- Post-solve disposition claim: single-writer per nonce.
local now = tonumber(redis.call('TIME')[1])
local existing = redis.call('GET', KEYS[1])
if not existing then
  local rec = {}
  rec['v'] = 1
  rec['state'] = 'pending'
  rec['owner'] = ARGV[1]
  rec['lease_until'] = now + tonumber(ARGV[2])
  rec['disposition'] = cjson.null
  redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', tonumber(ARGV[3]))
  return 'claimed'
end
local rec = cjson.decode(existing)
if rec['v'] ~= 1 then
  return 'pending'
end
if rec['state'] == 'complete' then
  return 'complete'
end
if rec['owner'] == ARGV[1] then
  return 'pending'
end
if tonumber(rec['lease_until']) > now then
  return 'pending'
end
rec['owner'] = ARGV[1]
rec['lease_until'] = now + tonumber(ARGV[2])
rec['disposition'] = cjson.null
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 'taken_over'
LUA;

    /**
     * Atomic finalize: pending(me) -> complete(disposition), keeping the
     * record TTL (KEEPTTL, Redis 6.0+). Refused (false) for a non-owner or
     * a non-pending record — never overwrites another owner's work.
     *   KEYS[1] = the record key
     *   ARGV[1] = owner token, ARGV[2] = disposition JSON
     */
    private const FINALIZE_LUA = <<<'LUA'
-- Post-solve disposition finalize: pending(owner) -> complete.
local existing = redis.call('GET', KEYS[1])
if not existing then
  return false
end
local rec = cjson.decode(existing)
if rec['v'] ~= 1 then
  return false
end
if rec['state'] ~= 'pending' then
  return false
end
if rec['owner'] ~= ARGV[1] then
  return false
end
rec['state'] = 'complete'
rec['owner'] = cjson.null
rec['lease_until'] = cjson.null
rec['disposition'] = cjson.decode(ARGV[2])
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return true
LUA;

    /**
     * @param \Predis\Client|\Redis $redis      the Redis client shared with
     *                                          the risk state
     * @param string                $namespace  the risk namespace (the
     *                                          hash-tag discriminator)
     * @param int                   $ttlSecs    the RECORD TTL (the extension
     *                                          wires Config::MAX_TTL_SECS +
     *                                          ttl margin); 0 = use the
     *                                          per-call claim TTL
     */
    public function __construct(
        private readonly \Predis\Client|\Redis $redis,
        private readonly string $namespace = 'kiwi',
        private readonly int $ttlSecs = 0,
    ) {
    }

    public function claim(string $nonce, string $owner, int $ttlSeconds): string
    {
        $recordTtl = max(1, $this->ttlSecs > 0 ? $this->ttlSecs : $ttlSeconds);
        $status = RedisEval::eval($this->redis, self::CLAIM_LUA, $this->key($nonce), [
            $owner,
            (string) self::LEASE_SECS,
            (string) $recordTtl,
        ]);

        return \is_string($status) && \in_array($status, ['claimed', 'pending', 'taken_over', 'complete'], true)
            ? $status
            : 'pending';
    }

    public function read(string $nonce): ?PostSolveDispositionRecord
    {
        $raw = $this->redis->get($this->key($nonce));
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $rec = json_decode($raw, true);
        if (!\is_array($rec) || ($rec['state'] ?? null) !== 'pending' && ($rec['state'] ?? null) !== 'complete') {
            return null;
        }

        $disposition = null;
        if (($rec['state'] ?? null) === 'complete' && \is_array($rec['disposition'] ?? null)) {
            $kind = PostSolveDispositionKind::tryFrom((string) ($rec['disposition']['kind'] ?? ''));
            if ($kind === null) {
                return null;
            }
            $disposition = new PostSolveDisposition(
                $kind,
                isset($rec['disposition']['decision_id']) && \is_string($rec['disposition']['decision_id']) ? $rec['disposition']['decision_id'] : null,
                isset($rec['disposition']['chain_id']) && \is_string($rec['disposition']['chain_id']) ? $rec['disposition']['chain_id'] : null,
            );
        }

        return new PostSolveDispositionRecord(
            (string) $rec['state'],
            isset($rec['owner']) && \is_string($rec['owner']) ? $rec['owner'] : null,
            isset($rec['lease_until']) && \is_int($rec['lease_until']) ? $rec['lease_until'] : null,
            $disposition,
        );
    }

    public function finalize(string $nonce, string $owner, PostSolveDisposition $disposition): bool
    {
        $ok = RedisEval::eval($this->redis, self::FINALIZE_LUA, $this->key($nonce), [
            $owner,
            (string) json_encode(self::wire($disposition), JSON_THROW_ON_ERROR),
        ]);

        return $ok === true || $ok === 1;
    }

    private function key(string $nonce): string
    {
        return sprintf('{kiwi:%s}:%s%s', $this->namespace, self::PREFIX, $nonce);
    }

    /**
     * The persisted disposition shape — kind / decision_id / chain_id
     * ONLY. Raw risk vectors, fingerprints and descriptors are never
     * stored.
     *
     * @return array{kind: string, decision_id: ?string, chain_id: ?string}
     */
    private static function wire(PostSolveDisposition $disposition): array
    {
        return [
            'kind' => $disposition->kind->value,
            'decision_id' => $disposition->decisionId,
            'chain_id' => $disposition->chainId,
        ];
    }
}
