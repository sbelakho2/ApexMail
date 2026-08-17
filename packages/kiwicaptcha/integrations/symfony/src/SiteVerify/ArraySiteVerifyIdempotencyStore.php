<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * In-memory idempotency store for tests/dev (single-process semantics).
 */
final class ArraySiteVerifyIdempotencyStore implements SiteVerifyIdempotencyStore
{
    /** @var array<string, array{hash: string, state: string, owner: string, result: ?array, lease_expires_at: int}> */
    private array $records = [];

    private readonly \Closure $now;

    /**
     * @param \Closure|null $now test seam: returns the current Unix seconds
     *                           used for lease comparisons (defaults to
     *                           time()); advancing it simulates lease expiry
     */
    public function __construct(?\Closure $now = null)
    {
        $this->now = $now ?? static fn (): int => time();
    }

    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds): array
    {
        $key = $this->key($backendId, $idempotencyKey);
        $existing = $this->records[$key] ?? null;
        if ($existing === null) {
            $owner = bin2hex(random_bytes(16));
            $this->records[$key] = [
                'hash' => $responseHash,
                'state' => 'pending',
                'owner' => $owner,
                'result' => null,
                'lease_expires_at' => ($this->now)() + self::LEASE_SECONDS,
            ];

            return [IdempotencyClaim::Claimed, $owner];
        }
        if ($existing['hash'] !== $responseHash) {
            return [IdempotencyClaim::Conflict, null];
        }
        if ($existing['state'] === 'complete') {
            return [IdempotencyClaim::CompleteSame, null];
        }

        return [IdempotencyClaim::PendingSame, null];
    }

    public function takeover(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds): array
    {
        $key = $this->key($backendId, $idempotencyKey);
        $existing = $this->records[$key] ?? null;
        $now = ($this->now)();
        if ($existing === null
            || $existing['state'] !== 'pending'
            || $existing['hash'] !== $responseHash
            || ($existing['lease_expires_at'] ?? 0) >= $now
        ) {
            return [IdempotencyClaim::StillPending, null];
        }
        $owner = bin2hex(random_bytes(16));
        $this->records[$key] = array_replace($existing, ['owner' => $owner, 'lease_expires_at' => $now + self::LEASE_SECONDS]);

        return [IdempotencyClaim::TookOver, $owner];
    }

    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
    {
        $key = $this->key($backendId, $idempotencyKey);
        $existing = $this->records[$key] ?? null;
        if ($existing === null || $existing['owner'] !== $owner) {
            return;
        }
        $this->records[$key] = array_replace($existing, ['state' => 'complete', 'result' => $canonicalResponse]);
    }

    public function stored(string $backendId, string $idempotencyKey): ?array
    {
        $existing = $this->records[$this->key($backendId, $idempotencyKey)] ?? null;
        if ($existing === null || $existing['state'] !== 'complete') {
            return null;
        }

        return $existing['result'];
    }

    private function key(string $backendId, string $idempotencyKey): string
    {
        return $backendId.':'.$idempotencyKey;
    }
}
