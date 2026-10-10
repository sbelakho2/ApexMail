<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * In-memory idempotency store for tests/dev (single-process semantics).
 *
 * It mirrors the Redis store's production state machine, not a
 * parallel one. Every entry is the exact canonical v2 record under an
 * out-of-band envelope that carries the key lifetime. The record is
 * validated through {@see SiteVerifyIdempotencyRecordSchema} before
 * every transition and read, and the lifetime is enforced at the start
 * of every operation: at the deadline the entry is gone, exactly like a
 * Redis expiry. A test that exercises the idempotency/replay behavior
 * here therefore observes the same logical state machine the production
 * store runs.
 */
final class ArraySiteVerifyIdempotencyStore implements SiteVerifyIdempotencyStore
{
    /**
     * finalize and renew do not know the original TTL; the Redis store
     * keeps the same conservative bounded window so completed entries
     * stay readable for retries.
     */
    private const RETENTION_SECONDS = 300;

    /** @var array<string, array{expiresAt: int, record: array<string, mixed>}> */
    private array $records = [];

    private readonly \Closure $now;

    /**
     * @param \Closure|null $now test seam returning the current Unix
     *                           seconds for the key lifetime and lease
     *                           comparisons; it defaults to time() and
     *                           advancing it simulates expiry.
     * @param int           $leaseSeconds the ownership lease window in
     *                                    seconds (defaults to the interface
     *                                    constant) — every claim, takeover
     *                                    and renew uses this value.
     */
    public function __construct(
        ?\Closure $now = null,
        private readonly int $leaseSeconds = self::LEASE_SECONDS,
    ) {
        $this->now = $now ?? static fn (): int => time();
    }

    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
    {
        SiteVerifyIdempotencyRecordSchema::assertCanonicalClaimIdentity($responseHash, $remoteipFingerprint, $binding);
        $key = $this->key($backendId, $idempotencyKey);
        $entry = $this->liveEntry($key);
        if ($entry === null) {
            $owner = bin2hex(random_bytes(16));
            $lease = $leaseSeconds ?? $this->leaseSeconds;
            $now = ($this->now)();
            $this->records[$key] = [
                'expiresAt' => $now + $ttlSeconds,
                'record' => [
                    'v' => SiteVerifyIdempotencyRecordSchema::VERSION_V2,
                    'response_hash' => $responseHash,
                    'remoteip_fingerprint' => $remoteipFingerprint,
                    'binding' => $binding ?? '',
                    'state' => 'pending',
                    'owner' => $owner,
                    'lease_expires_at' => $now + $lease,
                    'result' => null,
                ],
            ];

            return [IdempotencyClaim::Claimed, $owner];
        }
        $record = $entry['record'];
        if (
            $record['response_hash'] !== $responseHash
            || $record['remoteip_fingerprint'] !== $remoteipFingerprint
            || $record['binding'] !== ($binding ?? '')
        ) {
            return [IdempotencyClaim::Conflict, null];
        }
        if ($record['state'] === 'complete') {
            return [IdempotencyClaim::CompleteSame, null];
        }

        return [IdempotencyClaim::PendingSame, null];
    }

    public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds, string $remoteipFingerprint, ?int $leaseSeconds = null, ?string $binding = null): array
    {
        SiteVerifyIdempotencyRecordSchema::assertCanonicalClaimIdentity($responseHash, $remoteipFingerprint, $binding);
        $key = $this->key($backendId, $idempotencyKey);
        $entry = $this->liveEntry($key);
        $now = ($this->now)();
        if ($entry === null
            || $entry['record']['state'] !== 'pending'
            || $entry['record']['response_hash'] !== $responseHash
            || $entry['record']['remoteip_fingerprint'] !== $remoteipFingerprint
            || $entry['record']['binding'] !== ($binding ?? '')
            || $entry['record']['lease_expires_at'] >= $now
        ) {
            return [IdempotencyClaim::StillPending, null];
        }
        $owner = bin2hex(random_bytes(16));
        $entry['record']['owner'] = $owner;
        $entry['record']['lease_expires_at'] = $now + ($leaseSeconds ?? $this->leaseSeconds);
        $entry['expiresAt'] = $now + $ttlSeconds;
        $this->records[$key] = $entry;

        return [IdempotencyClaim::TookOver, $owner];
    }

    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): bool
    {
        $key = $this->key($backendId, $idempotencyKey);
        $entry = $this->liveEntry($key);
        if (
            $entry === null
            || $entry['record']['state'] !== 'pending'
            || $entry['record']['owner'] !== $owner
            || $entry['record']['response_hash'] !== $responseHash
        ) {
            return false;
        }
        SiteVerifyResult::validate($canonicalResponse);
        $entry['record']['state'] = 'complete';
        $entry['record']['owner'] = null;
        $entry['record']['lease_expires_at'] = null;
        $entry['record']['result'] = $canonicalResponse;
        $entry['expiresAt'] = ($this->now)() + self::RETENTION_SECONDS;
        $this->records[$key] = $entry;

        return true;
    }

    public function renew(string $backendId, string $idempotencyKey, string $owner): bool
    {
        $key = $this->key($backendId, $idempotencyKey);
        $entry = $this->liveEntry($key);
        if (
            $entry === null
            || $entry['record']['state'] !== 'pending'
            || $entry['record']['owner'] !== $owner
        ) {
            return false;
        }
        $now = ($this->now)();
        $entry['record']['lease_expires_at'] = $now + $this->leaseSeconds;
        $entry['expiresAt'] = $now + self::RETENTION_SECONDS;
        $this->records[$key] = $entry;

        return true;
    }

    public function leaseSeconds(): int
    {
        return $this->leaseSeconds;
    }

    public function storedForOperation(string $backendId, string $idempotencyKey, string $responseHash, string $remoteipFingerprint, ?string $binding = null): StoredLookup
    {
        $key = $this->key($backendId, $idempotencyKey);
        try {
            $entry = $this->liveEntry($key);
        } catch (SiteVerifyIdempotencyCorruptException) {
            return StoredLookup::corrupt();
        }
        if ($entry === null) {
            return StoredLookup::missing();
        }
        $record = $entry['record'];
        if (
            $record['response_hash'] !== $responseHash
            || $record['remoteip_fingerprint'] !== $remoteipFingerprint
            || $record['binding'] !== ($binding ?? '')
        ) {
            // The key now holds a different operation (an ABA/reuse): the
            // caller must never accept the new operation's result.
            return StoredLookup::changed();
        }
        if ($record['state'] !== 'complete') {
            return StoredLookup::pendingSame();
        }
        $result = $record['result'] ?? null;
        if (!\is_array($result)) {
            return StoredLookup::corrupt();
        }
        SiteVerifyResult::validate($result);

        return StoredLookup::completeSame($result);
    }

    /**
     * The lifetime-enforcing entry read every operation starts with: the
     * validated v2 record plus its envelope, or null when the entry is
     * missing or at/past its deadline (the Redis expiry semantics). The
     * record is validated through the shared schema first, so corruption
     * fails closed exactly like the production store.
     *
     * @return array{expiresAt: int, record: array<string, mixed>}|null
     */
    private function liveEntry(string $key): ?array
    {
        $entry = $this->records[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        if (($this->now)() >= $entry['expiresAt']) {
            unset($this->records[$key]);

            return null;
        }
        SiteVerifyIdempotencyRecordSchema::validate($entry['record']);

        return $entry;
    }

    private function key(string $backendId, string $idempotencyKey): string
    {
        return $backendId.':'.$idempotencyKey;
    }
}
