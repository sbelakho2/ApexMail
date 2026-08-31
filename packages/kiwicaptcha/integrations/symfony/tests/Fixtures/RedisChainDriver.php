<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;

/**
 * The real-Redis driver for the model-checking walk: every transition is
 * the Lua script of RedisChainedChallengeStateStore. The TTL/lease
 * transitions are driven by direct key manipulation (the record TTL is
 * preserved), the real-Redis equivalent of the in-memory driver's clock
 * advance. An expired lease is rewritten to the past, and an expired
 * chain has its record + obligation mapping deleted, exactly what the
 * TTL does.
 */
final class RedisChainDriver implements ChainStoreDriver
{
    private readonly RedisChainedChallengeStateStore $store;

    public function __construct(private readonly \Predis\Client $client, private readonly string $namespace)
    {
        $this->store = new RedisChainedChallengeStateStore($client, $namespace);
    }

    public function now(): int
    {
        $time = $this->client->time();
        if (\is_array($time) && isset($time[0])) {
            return (int) $time[0];
        }

        return time();
    }

    private function chainKey(string $chainId): string
    {
        return sprintf('{kiwi:%s}:chain:%s', $this->namespace, $chainId);
    }

    private function obligationKey(string $obligationId): string
    {
        return sprintf('{kiwi:%s}:chain-obligation:%s', $this->namespace, $obligationId);
    }

    public function obligationChainId(string $obligationId): ?string
    {
        $chainId = $this->client->get($this->obligationKey($obligationId));
        if (!\is_string($chainId) || $chainId === '') {
            return null;
        }

        return $chainId;
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
        $key = $this->chainKey($chainId);
        $raw = $this->client->get($key);
        if (!\is_string($raw)) {
            return false;
        }
        try {
            $record = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return false;
        }
        if (!\is_array($record) || ($record['state'] ?? null) !== 'reserved' || ($record['leaseUntil'] ?? null) === null) {
            return false;
        }
        if ((int) $record['leaseUntil'] + 1 >= (int) $record['expiresAt']) {
            // The lease is capped by the remaining TTL: advancing past it
            // would also expire the chain (a different transition).
            return false;
        }
        $record['leaseUntil'] = $this->now() - 1;
        $ttl = max(1, (int) $this->client->ttl($key));
        $this->client->set($key, (string) json_encode($record, JSON_THROW_ON_ERROR), 'EX', $ttl);

        return true;
    }

    public function expireChain(string $chainId, string $obligationId): bool
    {
        $applied = false;
        if ((int) $this->client->exists($this->chainKey($chainId)) === 1) {
            $this->client->del($this->chainKey($chainId));
            $applied = true;
        }
        if ((int) $this->client->exists($this->obligationKey($obligationId)) === 1) {
            $this->client->del($this->obligationKey($obligationId));
            $applied = true;
        }

        return $applied;
    }
}
