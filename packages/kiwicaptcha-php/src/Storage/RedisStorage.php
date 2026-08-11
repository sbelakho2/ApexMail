<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ChallengeRecord;

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
 * Records are stored as JSON (`json_encode($record->toArray())` —
 * LANGUAGE-NEUTRAL: a Rust service using the same Redis instance can read
 * them, and vice versa; the record's TTL is the key expiration). The JSON
 * keys match the Rust serde schema exactly.
 *
 * Implements {@see \KiwiCaptcha\AtomicStorageInterface}: GETDEL makes
 * consume() strict single-use under concurrency.
 */
final class RedisStorage implements AtomicStorageInterface
{
    private const GETDEL_SCRIPT = 'return redis.call("GETDEL", KEYS[1])';

    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly string $prefix = 'kiwicaptcha:',
    ) {
    }

    public function store(ChallengeRecord $record): void
    {
        $key = $this->prefix.$record->nonce;
        $value = json_encode($record->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
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

    /**
     * Decode a stored JSON value back into a record.
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

        try {
            return ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return null;
        }
    }
}
