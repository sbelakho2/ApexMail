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
        $value = json_encode($record->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
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
