<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\StorageInterface;

/**
 * Redis-backed storage with TRUE atomic single-use semantics.
 *
 * `consume()` uses Redis GETDEL, which atomically returns and deletes the
 * key — two concurrent consumers can never both win. GETDEL requires
 * Redis 6.2+.
 *
 * - phpredis (\Redis): GETDEL via rawCommand().
 * - Predis: GETDEL via an inline Lua script (the eval path used here has no
 *   fallback — the server MUST be Redis 6.2+).
 *
 * Records are stored as `serialize($record->toArray())` with the record's
 * TTL as the key expiration. Attempt counters are stored on a separate key
 * (`<prefix><nonce>:attempts`) incremented atomically in Lua, with an
 * expiration set on first increment so stale counters cannot accumulate.
 * The Lua script is existence-aware: the counter key is only created when
 * the challenge record itself exists, so random/fake nonces never litter
 * Redis with 1h-TTL keys.
 */
final class RedisStorage implements StorageInterface
{
    private const ATTEMPTS_SUFFIX = ':attempts';

    /**
     * Safety-net TTL for attempt counters. The challenge record itself carries
     * the authoritative TTL, but the counter key is created before consume()
     * (when the record TTL is not yet available), so a fixed ceiling keeps
     * stale keys from accumulating indefinitely.
     */
    private const ATTEMPTS_TTL_SECS = 3600;

    /**
     * Existence-aware attempt counting: the challenge key must exist before
     * the counter is touched, so random/fake nonces never create Redis keys
     * (they previously left 1h-TTL counter keys behind on every submit).
     *
     * KEYS[1]  = challenge key (<prefix><nonce>)
     * KEYS[2]  = attempt counter key (<prefix><nonce>:attempts)
     * ARGV[1]  = maxAttempts
     * ARGV[2]  = TTL in seconds
     *
     * Returns: -1 = no challenge record (counter untouched, no key created);
     *           1 = cap exceeded (counter left incremented); 0 = recorded.
     */
    private const INCREMENT_SCRIPT = <<<'LUA'
if redis.call('EXISTS', KEYS[1]) == 0 then
    return -1
end
local n = redis.call('INCR', KEYS[2])
if n == 1 then
    redis.call('EXPIRE', KEYS[2], ARGV[2])
end
if n > tonumber(ARGV[1]) then
    return 1
end
return 0
LUA;

    private const GETDEL_SCRIPT = 'return redis.call("GETDEL", KEYS[1])';

    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly string $prefix = 'kiwicaptcha:',
    ) {
    }

    public function store(ChallengeRecord $record): void
    {
        $key = $this->prefix.$record->nonce;
        $value = serialize($record->toArray());
        $ttl = max(1, $record->expiresAt - time());

        if ($this->client instanceof \Redis) {
            $this->client->set($key, $value, ['EX' => $ttl]);
        } else {
            $this->client->set($key, $value, 'EX', $ttl);
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

    public function consume(string $nonce): ?ChallengeRecord
    {
        $key = $this->prefix.$nonce;

        if ($this->client instanceof \Redis) {
            $raw = $this->client->rawCommand('GETDEL', $key);
        } else {
            $raw = $this->client->eval(self::GETDEL_SCRIPT, 1, $key);
        }
        if ($raw === false || $raw === null) {
            return null;
        }

        return $this->decode((string) $raw);
    }

    public function delete(string $nonce): void
    {
        $this->client->del($this->prefix.$nonce);
    }

    public function attemptsUsed(string $nonce): int
    {
        $raw = $this->client->get($this->prefix.$nonce.self::ATTEMPTS_SUFFIX);

        return (int) $raw;
    }

    public function incrementAttempts(string $nonce, int $maxAttempts): bool
    {
        $result = $this->eval(
            self::INCREMENT_SCRIPT,
            [
                $this->prefix.$nonce,
                $this->prefix.$nonce.self::ATTEMPTS_SUFFIX,
            ],
            [(string) $maxAttempts, (string) self::ATTEMPTS_TTL_SECS],
        );

        // -1: no challenge record exists — the counter was NOT incremented
        // and no key was created. Not a cap rejection: return true so the
        // verifier proceeds to consume(), which returns null and fails with
        // RecordNotFound — the same outcome as before, minus the key litter.
        return $result !== 1;
    }

    /**
     * Run a Lua script against whichever client implementation is in use.
     *
     * @param list<string> $keys
     * @param list<string> $args
     */
    private function eval(string $script, array $keys, array $args): mixed
    {
        if ($this->client instanceof \Redis) {
            // phpredis signature: eval($script, $args, $numKeys)
            return $this->client->eval($script, [...$keys, ...$args], \count($keys));
        }

        // Predis signature: eval($script, $numkeys, ...$keysAndArgs)
        return $this->client->eval($script, \count($keys), ...$keys, ...$args);
    }

    private function decode(string $raw): ?ChallengeRecord
    {
        // @: unserialize warns on malformed input; the failure is intentional
        // and handled by returning null (a corrupt key must not blow up the
        // verify path).
        try {
            $data = @unserialize($raw, ['allowed_classes' => false]);
        } catch (\Throwable) {
            return null;
        }
        if (!\is_array($data)) {
            return null;
        }

        try {
            return ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return null;
        }
    }
}
