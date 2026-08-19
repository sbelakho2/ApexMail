<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * In-memory chained-challenge state store for tests/dev (single-process
 * semantics), mirroring the Redis store's three-state machine exactly:
 * available -> reserved (idempotent for the same chain id) -> consumed
 * (one-shot GET+DEL equivalent), with release undoing a reservation. A
 * consumed chain id stays as a tombstone so a replayed ticket is refused
 * with the same 'consumed' outcome as the Redis store.
 *
 * Clock-less: TTL expiry is not enforced here — the ticket service's
 * signed expiresAt is the authoritative expiry check, and the Redis
 * store's EXPIRE mirrors it for the production key.
 */
final class ArrayChainedChallengeStateStore implements ChainedChallengeStateStore
{
    /**
     * @var array<string, array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: ?string, state: 'available'|'reserved'|'consumed'}>
     */
    private array $records = [];

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null): void
    {
        $this->records[$chainId] = [
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'requestBinding' => $requestBinding,
            'requiredAction' => $requiredAction,
            'state' => 'available',
        ];
    }

    public function reserve(string $chainId, int $ttlSecs): string
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'consumed') {
            return 'consumed';
        }
        if ($record['state'] === 'reserved') {
            return 'reserved';
        }
        $this->records[$chainId]['state'] = 'reserved';

        return 'available';
    }

    public function consume(string $chainId): ?array
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null || $record['state'] === 'consumed') {
            // At most ONE consumer ever wins (a consumed tombstone is
            // never consumed twice — mirroring the Redis GET+DEL).
            return null;
        }
        // Tombstone: a replayed ticket lands on the 'consumed' outcome.
        $this->records[$chainId]['state'] = 'consumed';

        return $record;
    }

    public function release(string $chainId): void
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null || $record['state'] !== 'reserved') {
            return;
        }
        $this->records[$chainId]['state'] = 'available';
    }
}
