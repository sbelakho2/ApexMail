<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * In-memory chained-challenge state store for tests/dev (single-process
 * semantics). Clock-less: TTL expiry is not enforced here — the ticket
 * service's signed expiresAt is the authoritative expiry check, and the
 * Redis store's EXPIRE mirrors it for the production key.
 */
final class ArrayChainedChallengeStateStore implements ChainedChallengeStateStore
{
    /** @var array<string, array{stage1Nonce: string, scope: string}> */
    private array $records = [];

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs): void
    {
        $this->records[$chainId] = ['stage1Nonce' => $stage1Nonce, 'scope' => $scope];
    }

    public function consume(string $chainId): ?array
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null) {
            return null;
        }
        unset($this->records[$chainId]);

        return $record;
    }
}
