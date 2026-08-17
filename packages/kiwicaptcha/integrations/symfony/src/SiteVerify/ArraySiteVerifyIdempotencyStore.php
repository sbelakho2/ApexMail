<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * In-memory idempotency store for tests/dev (single-process semantics).
 */
final class ArraySiteVerifyIdempotencyStore implements SiteVerifyIdempotencyStore
{
    /** @var array<string, array{hash: string, state: string, owner: string, result: ?array}> */
    private array $records = [];

    public function claim(string $backendId, string $idempotencyKey, string $responseHash, int $ttlSeconds): array
    {
        $key = $this->key($backendId, $idempotencyKey);
        $existing = $this->records[$key] ?? null;
        if ($existing === null) {
            $owner = bin2hex(random_bytes(16));
            $this->records[$key] = ['hash' => $responseHash, 'state' => 'pending', 'owner' => $owner, 'result' => null];

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

    public function finalize(string $backendId, string $idempotencyKey, string $responseHash, string $owner, array $canonicalResponse): void
    {
        $key = $this->key($backendId, $idempotencyKey);
        $existing = $this->records[$key] ?? null;
        if ($existing === null || $existing['owner'] !== $owner) {
            return;
        }
        $this->records[$key] = ['hash' => $responseHash, 'state' => 'complete', 'owner' => $owner, 'result' => $canonicalResponse];
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
