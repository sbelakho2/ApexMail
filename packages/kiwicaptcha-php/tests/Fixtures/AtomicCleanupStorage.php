<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\DeleteIfPendingResult;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;

/**
 * An ArrayStorage wrapper advertising the atomic cleanup capability,
 * with call counters. The verifier-level wiring tests assert that the
 * cheap-failure cleanup goes through the single fused transition, with
 * no separate consumedState read plus delete pair, and that the
 * no-delete exception (MissingClientIp on a pending record) bypasses it.
 */
final class AtomicCleanupStorage implements StorageInterface, AtomicDeleteIfPendingInterface, OperationIdentityAwareStorageInterface
{
    public int $deleteIfPendingCalls = 0;
    public int $consumedStateCalls = 0;
    public int $deleteCalls = 0;

    public function __construct(private readonly ArrayStorage $inner = new ArrayStorage())
    {
    }

    public function store(ChallengeRecord $record): void
    {
        $this->inner->store($record);
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->inner->find($nonce);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        $this->consumedStateCalls++;

        return $this->inner->consumedState($nonce);
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        return $this->inner->consume($nonce);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->inner->commitResult($nonce, $valid, $binding);
    }

    public function delete(string $nonce): void
    {
        $this->deleteCalls++;
        $this->inner->delete($nonce);
    }

    public function deleteIfPending(string $nonce): DeleteIfPendingResult
    {
        $this->deleteIfPendingCalls++;
        if ($this->inner->find($nonce) === null) {
            return new DeleteIfPendingResult('missing');
        }
        $consumed = $this->inner->consumedState($nonce);
        if ($consumed === null) {
            $this->inner->delete($nonce);

            return new DeleteIfPendingResult('deleted-pending');
        }

        return new DeleteIfPendingResult('consumed', $consumed);
    }
}
