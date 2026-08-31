<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;

/**
 * The in-memory store driver for the model-checking walk: a controllable
 * clock (the same closure the store reads), so the TTL/lease transitions
 * are enforced deterministically, mirroring the redis TIME semantics.
 */
final class ArrayChainDriver implements ChainStoreDriver
{
    private int $clock;

    private ArrayChainedChallengeStateStore $store;

    public function __construct(int $initialClock = 1_000_000)
    {
        $this->clock = $initialClock;
        $this->store = new ArrayChainedChallengeStateStore(function (): float {
            return (float) $this->clock;
        });
    }

    public function store(): ArrayChainedChallengeStateStore
    {
        return $this->store;
    }

    public function now(): int
    {
        return $this->clock;
    }

    public function obligationChainId(string $obligationId): ?string
    {
        return $this->store->obligationChainId($obligationId);
    }

    public function createOrGet(string $chainId, string $obligationId, int $rank, int $expiresAt): string
    {
        return $this->store->createOrGetObligation(
            $obligationId,
            $chainId,
            ChainStateWalk::S1_NONCE,
            'login',
            'txn-alpha',
            ChainStateWalk::RANKS[$rank],
            $rank,
            1,
            $expiresAt,
            300,
        );
    }

    public function read(string $chainId): ?array
    {
        return $this->store->read($chainId);
    }

    public function reserve(string $chainId, string $ownerToken): string
    {
        return $this->store->reserve($chainId, $ownerToken, 15);
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $this->store->release($chainId, $ownerToken);
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        return $this->store->markIssued($chainId, $ownerToken, $stage2Nonce);
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        return $this->store->markVerified($chainId, $stage2Nonce);
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        return $this->store->markStepUpRequired($chainId, $stage2Nonce);
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        return $this->store->markDenied($chainId, $stage2Nonce);
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        return $this->store->markTransactionDenied($chainId, $obligationId);
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        return $this->store->markTransactionStepUpRequired($chainId, $obligationId);
    }

    public function rearmIssued(string $chainId, string $stage2Nonce): bool
    {
        return $this->store->rearmIssued($chainId, $stage2Nonce);
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        $this->store->deleteObligation($chainId, $obligationId);
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->store->complete($chainId, $ownerToken, $stage2Nonce);
    }

    public function advanceLease(string $chainId): bool
    {
        $record = $this->store->read($chainId);
        if ($record === null || $record['state'] !== 'reserved' || $record['leaseUntil'] === null) {
            return false;
        }
        if ($record['leaseUntil'] + 1 >= $record['expiresAt']) {
            // The lease is capped by the remaining TTL: advancing past it
            // would also expire the chain (a different transition).
            return false;
        }
        $this->clock = max($this->clock, $record['leaseUntil'] + 1);

        return true;
    }

    public function expireChain(string $chainId, string $obligationId): bool
    {
        $record = $this->store->read($chainId);
        if ($record !== null) {
            $this->clock = max($this->clock, $record['expiresAt'] + 1);

            return true;
        }
        if ($this->store->obligationChainId($obligationId) !== null) {
            $this->clock += 1000;

            return true;
        }

        return false;
    }
}
